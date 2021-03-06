/*
 * This file is part of libicd-wireguard
 *
 * Copyright (C) 2021, Merlijn Wajer <merlijn@wizzup.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 3.0 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include "libicd_network_wireguard.h"

void wireguard_state_change(network_wireguard_private * private,
			    wireguard_network_data * network_data, network_wireguard_state new_state, int source)
{
	network_wireguard_state current_state = private->state;

	if (source == EVENT_SOURCE_IP_UP) {
		if (current_state.iap_connected) {
			WN_ERR("ip_up called when we are already connected\n");
			/* Figure out how to handle this */
		}

		/* Add network to network_data */
		private->network_data_list = g_slist_prepend(private->network_data_list, network_data);

		if (new_state.service_provider_mode) {
			/* Return right away, wait for dbus calls */
			network_data->ip_up_cb(ICD_NW_SUCCESS, NULL, network_data->ip_up_cb_token, NULL);

		} else {

			/* Check if we want to start Tor (system wide enabled), or if we just
			 * call the callback right now */
			if (current_state.system_wide_enabled) {
				int start_ret = 0;

				start_ret = startup_wireguard(network_data, new_state.active_config);

				if (start_ret != 0) {
					icd_nw_ip_up_cb_fn up_cb = network_data->ip_up_cb;
					gpointer up_token = network_data->ip_up_cb_token;

					if (start_ret == 1) {
						network_free_all(network_data);
					}

					new_state.iap_connected = FALSE;
					up_cb(ICD_NW_ERROR, NULL, up_token);
				} else {
					new_state.wg_quick_running = TRUE;
					new_state.wireguard_running = TRUE;
					new_state.wireguard_up = FALSE;
					/* ip_up_cb will be called later in the bootstrap pid exit */
				}
			} else {
				/* System wide is disabled, so let's just call ip_up_cb right away */
				network_data->ip_up_cb(ICD_NW_SUCCESS, NULL, network_data->ip_up_cb_token, NULL);
			}
		}

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_IP_DOWN) {
		icd_nw_ip_down_cb_fn down_cb = network_data->ip_down_cb;
		gpointer down_token = network_data->ip_down_cb_token;

		/* Stop Tor etc, free network data */
		network_stop_all(network_data);
		network_free_all(network_data);

		new_state.wireguard_up = FALSE;
		new_state.wg_quick_running = FALSE;
		new_state.wireguard_running = FALSE;
		new_state.service_provider_mode = FALSE;

		down_cb(ICD_NW_SUCCESS, down_token);

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_GCONF_CHANGE) {
		WN_INFO("Wireguard system_wide status changed via gconf");

		/* We don't act on this in service provider mode */
		if (!current_state.service_provider_mode && current_state.iap_connected) {
			wireguard_network_data *network_data = icd_wireguard_find_first_network_data(private);

			if (network_data == NULL) {
				WN_ERR("iap_connected is TRUE, but we have no network_data");
			} else {
				if (new_state.system_wide_enabled
				    && current_state.system_wide_enabled != new_state.system_wide_enabled) {
					int start_ret = 0;

					new_state.gconf_transition_ongoing = TRUE;

					start_ret = startup_wireguard(network_data, new_state.active_config);

					if (start_ret == 1) {
						WN_ERR("Could not start Tor triggered through gconf change");
						private->close_cb(ICD_NW_ERROR,
								  "Could not launch Tor on gconf request",
								  network_data->network_type,
								  network_data->network_attrs,
								  network_data->network_id);
					} else if (start_ret == 0) {
						new_state.wg_quick_running = TRUE;
						new_state.wireguard_running = TRUE;
						new_state.wireguard_up = FALSE;
					}
				} else {
					new_state.gconf_transition_ongoing = TRUE;
					network_stop_all(network_data);
					/* TODO: review this, this is just ugly, but the reason we do this is
					 * because we cannot detect interface going down if it never goes up
					 * successfully, since we guard that with wireguard_interface_up, so
					 * that needs fixing, but for now we work around it here */

					new_state.wireguard_running = FALSE;
					new_state.wireguard_up = FALSE;
					new_state.wireguard_interface_up = FALSE;
				}

				emit_status_signal(new_state);
			}
		}
	} else if (source == EVENT_SOURCE_DBUS_CALL_START) {
		if (!current_state.service_provider_mode) {
			WN_ERR("Got EVENT_SOURCE_DBUS_CALL_START while not in provider mode");
			goto done;
		}

		wireguard_network_data *network_data = icd_wireguard_find_first_network_data(private);
		if (network_data == NULL) {
			WN_ERR("service_provider_module is TRUE, but we have no network_data");
			goto done;
		}

		int start_ret = 0;
		start_ret = startup_wireguard(network_data, new_state.active_config);

		if (start_ret != 0) {
			new_state.dbus_failed_to_start = TRUE;
			goto done;
		}

		new_state.wg_quick_running = TRUE;
		new_state.wireguard_running = TRUE;
		new_state.wireguard_up = FALSE;

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_DBUS_CALL_STOP) {
		if (!current_state.service_provider_mode) {
			WN_ERR("Got EVENT_SOURCE_DBUS_CALL_STOP while not in provider mode");
			goto done;
		}

		wireguard_network_data *network_data = icd_wireguard_find_first_network_data(private);
		if (network_data == NULL) {
			WN_ERR("service_provider_module is TRUE, but we have no network_data");
			goto done;
		}

		network_stop_all(network_data);
		/* TODO: review this, this is just ugly, but the reason we do this is
		 * because we cannot detect interface going down if it never goes up
		 * successfully, since we guard that with wireguard_interface_up, so
		 * that needs fixing, but for now we work around it here */
		new_state.wireguard_running = FALSE;
		new_state.wireguard_up = FALSE;
		new_state.wireguard_interface_up = FALSE;
	} else if (source == EVENT_SOURCE_WIREGUARD_UP) {
		WN_INFO("Wireguard interface went up");

		wireguard_network_data *network_data = icd_wireguard_find_first_network_data(private);
		if (network_data == NULL) {
			WN_ERR("We have no network data");
			goto done;
		}

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_WIREGUARD_DOWN) {
		WN_INFO("Wireguard interface went down");

		wireguard_network_data *network_data = icd_wireguard_find_first_network_data(private);
		if (network_data == NULL) {
			WN_ERR("We have no network data");
			goto done;
		}

		/* In service provider mode, I suppose this is fatal, but we can just
		 * emit the signal and have the service provider bring down the network */

		if (!current_state.wireguard_running) {
			WN_ERR("Received wireguard interface down but we did not know it was up");
			/* Figure out how to handle this */
		} else {
			if (current_state.service_provider_mode) {
				/* Nothing more to do, service provider will pick it up */
			} else if (current_state.gconf_transition_ongoing) {
				new_state.gconf_transition_ongoing = FALSE;
			} else {
				/* This will call ip down, so we don't free/stop here, since
				 * ip_down should be called */
				private->close_cb(ICD_NW_ERROR,
						  "Wireguard interface down (unexpectedly)",
						  network_data->network_type,
						  network_data->network_attrs, network_data->network_id);
			}
		}

		emit_status_signal(new_state);
	} else if (source == EVENT_SOURCE_WIREGUARD_QUICK_PID_EXIT) {
		network_data->wg_quick_pid = 0;

		if (new_state.wireguard_up) {
			new_state.iap_connected = TRUE;

			if (current_state.service_provider_mode) {
				/* Nothing more to do here */
			} else if (current_state.gconf_transition_ongoing) {
				new_state.gconf_transition_ongoing = FALSE;
			} else {
				network_data->ip_up_cb(ICD_NW_SUCCESS, NULL, network_data->ip_up_cb_token, NULL);
			}
		} else {
			if (current_state.service_provider_mode) {
				/* We should probably signal service_provider that we could
				 * not connect to Tor somehow, although the Stopped signal
				 * should tell it enough? */
			} else if (current_state.gconf_transition_ongoing) {
				new_state.gconf_transition_ongoing = FALSE;
			} else {
				icd_nw_ip_up_cb_fn up_cb = network_data->ip_up_cb;
				gpointer up_token = network_data->ip_up_cb_token;

				/* Maybe we should not free here */
				new_state.iap_connected = FALSE;
				network_stop_all(network_data);
				/* TODO: review this, this is just ugly, but the reason we do this is
				 * because we cannot detect interface going down if it never goes up
				 * successfully, since we guard that with wireguard_interface_up, so
				 * that needs fixing, but for now we work around it here */
				new_state.wireguard_running = FALSE;
				new_state.wireguard_up = FALSE;
				new_state.wireguard_interface_up = FALSE;

				network_free_all(network_data);

				up_cb(ICD_NW_ERROR, NULL, up_token);
			}
		}

		emit_status_signal(new_state);
	}

 done:
	/* Free old active_config if it is not the same pointer as in new_state */
	if (current_state.active_config != NULL && current_state.active_config != new_state.active_config) {
		free(current_state.active_config);
	}
	/* Move to new state */
	memcpy(&private->state, &new_state, sizeof(network_wireguard_state));
}

/** Function for configuring an IP address.
 * @param network_type network type
 * @param network_attrs attributes, such as type of network_id, security, etc.
 * @param network_id IAP name or local id, e.g. SSID
 * @param interface_name interface that was enabled
 * @param link_up_cb callback function for notifying ICd when the IP address
 *        is configured
 * @param link_up_cb_token token to pass to the callback function
 * @param private a reference to the icd_nw_api private memeber
 */
static void wireguard_ip_up(const gchar * network_type,
			    const guint network_attrs,
			    const gchar * network_id,
			    const gchar * interface_name,
			    icd_nw_ip_up_cb_fn ip_up_cb, gpointer ip_up_cb_token, gpointer * private)
{
	network_wireguard_private *priv = *private;
	WN_DEBUG("wireguard_ip_up");

	wireguard_network_data *network_data = g_new0(wireguard_network_data, 1);

	network_data->network_type = g_strdup(network_type);
	network_data->network_attrs = network_attrs;
	network_data->network_id = g_strdup(network_id);

	network_data->ip_up_cb = ip_up_cb;
	network_data->ip_up_cb_token = ip_up_cb_token;
	network_data->private = priv;

	network_wireguard_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
	new_state.iap_connected = TRUE;

	if (network_is_wireguard_provider(network_id, NULL)) {
		new_state.service_provider_mode = TRUE;
		new_state.active_config = NULL;
	} else {
		new_state.service_provider_mode = FALSE;
		new_state.active_config = get_active_config();
	}

	wireguard_state_change(priv, network_data, new_state, EVENT_SOURCE_IP_UP);

	return;
}

/**
 * Function for deconfiguring the IP layer, e.g. relasing the IP address.
 * Normally this function need not to be provided as the libicd_network_ipv4
 * network module provides IP address deconfiguration in a generic fashion.
 *
 * @param network_type      network type
 * @param network_attrs     attributes, such as type of network_id, security,
 *                          etc.
 * @param network_id        IAP name or local id, e.g. SSID
 * @param interface_name    interface name
 * @param ip_down_cb        callback function for notifying ICd when the IP
 *                          address is deconfigured
 * @param ip_down_cb_token  token to pass to the callback function
 * @param private           a reference to the icd_nw_api private member
 */
static void
wireguard_ip_down(const gchar * network_type, guint network_attrs,
		  const gchar * network_id, const gchar * interface_name,
		  icd_nw_ip_down_cb_fn ip_down_cb, gpointer ip_down_cb_token, gpointer * private)
{
	WN_DEBUG("wireguard_ip_down");
	network_wireguard_private *priv = *private;

	wireguard_network_data *network_data = icd_wireguard_find_network_data(network_type, network_attrs, network_id,
									       priv);

	network_data->ip_down_cb = ip_down_cb;
	network_data->ip_down_cb_token = ip_down_cb_token;

	network_wireguard_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
	new_state.iap_connected = FALSE;
	new_state.service_provider_mode = FALSE;

	wireguard_state_change(priv, network_data, new_state, EVENT_SOURCE_IP_DOWN);
}

static void wireguard_network_destruct(gpointer * private)
{
	network_wireguard_private *priv = *private;

	WN_DEBUG("wireguard_network_destruct");

	if (priv->gconf_client != NULL) {
		if (priv->gconf_cb_id_systemwide != 0) {
			gconf_client_notify_remove(priv->gconf_client, priv->gconf_cb_id_systemwide);
			priv->gconf_cb_id_systemwide = 0;
		}

		g_object_unref(priv->gconf_client);
	}
	free_wireguard_dbus();

	if (priv->network_data_list)
		WN_CRIT("ipv4 still has connected networks");

	g_free(priv);
}

/**
 * Function to handle child process termination
 *
 * @param pid         the process id that exited
 * @param exit_value  process exit value
 * @param private     a reference to the icd_nw_api private member
 */
static void wireguard_child_exit(const pid_t pid, const gint exit_status, gpointer * private)
{
	GSList *l;
	network_wireguard_private *priv = *private;
	wireguard_network_data *network_data;

	enum pidtype { UNKNOWN, WG_QUICK_PID };

	int pid_type = UNKNOWN;

	for (l = priv->network_data_list; l; l = l->next) {
		network_data = (wireguard_network_data *) l->data;
		if (network_data) {
			if (network_data->wg_quick_pid == pid) {
				pid_type = WG_QUICK_PID;
				break;
			}
			/* Do we want to do anything with unknown pids? */

		} else {
			/* This can happen if we are manually disconnecting, and we already
			   free the network data and kill tor, then we won't have the
			   network_data anymore */
			WN_DEBUG("wireguard_child_exit: network_data_list contains empty network_data");
		}
	}

	if (!l) {
		WN_ERR("wireguard_child_exit: got pid %d but did not find network_data\n", pid);
		return;
	}

	if (pid_type == WG_QUICK_PID) {
		WN_INFO("Got wg-quick pid: %d with status %d", pid, exit_status);

		network_wireguard_state new_state;
		memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
		new_state.wg_quick_running = FALSE;

		if (exit_status == 0) {
			new_state.wireguard_up = TRUE;
		} else {
			WN_WARN("wg-quick failed with %d\n", exit_status);
			new_state.wireguard_up = FALSE;
		}

		wireguard_state_change(priv, network_data, new_state, EVENT_SOURCE_WIREGUARD_QUICK_PID_EXIT);
	}

	return;
}

static void gconf_callback(GConfClient * client, guint cnxn_id, GConfEntry * entry, gpointer user_data)
{
	network_wireguard_private *priv = user_data;
	gboolean system_wide_enabled = gconf_value_get_bool(entry->value);

	network_wireguard_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
	new_state.system_wide_enabled = system_wide_enabled;
	wireguard_state_change(priv, NULL, new_state, EVENT_SOURCE_GCONF_CHANGE);
}

/** Tor network module initialization function.
 * @param network_api icd_nw_api structure filled in by the module
 * @param watch_cb function to inform ICd that a child process is to be
 *        monitored for exit status
 * @param watch_cb_token token to pass to the watch pid function
 * @param close_cb function to inform ICd that the network connection is to be
 *        closed
 * @return TRUE on succes; FALSE on failure whereby the module is unloaded
 */
gboolean icd_nw_init(struct icd_nw_api *network_api,
		     icd_nw_watch_pid_fn watch_fn, gpointer watch_fn_token,
		     icd_nw_close_fn close_fn, icd_nw_status_change_fn status_change_fn, icd_nw_renew_fn renew_fn)
{
	network_wireguard_private *priv = g_new0(network_wireguard_private, 1);

	network_api->version = ICD_NW_MODULE_VERSION;
	network_api->ip_up = wireguard_ip_up;
	network_api->ip_down = wireguard_ip_down;

	priv->state.system_wide_enabled = get_system_wide_enabled();
	priv->state.active_config = NULL;
	priv->state.iap_connected = FALSE;
	priv->state.service_provider_mode = FALSE;

	priv->state.wg_quick_running = FALSE;
	priv->state.wireguard_running = FALSE;
	priv->state.wireguard_up = FALSE;
	priv->state.wireguard_interface_up = FALSE;
	priv->state.wireguard_interface_index = -1;
	priv->state.gconf_transition_ongoing = FALSE;
	priv->state.dbus_failed_to_start = FALSE;

	priv->gconf_client = gconf_client_get_default();
	GError *error = NULL;
	gconf_client_add_dir(priv->gconf_client, GC_NETWORK_TYPE, GCONF_CLIENT_PRELOAD_NONE, &error);
	if (error != NULL) {
		WN_ERR("Could not monitor gconf dir for changes");
		g_clear_error(&error);
		goto err;
	}
	priv->gconf_cb_id_systemwide =
	    gconf_client_notify_add(priv->gconf_client, GC_WIREGUARD_SYSTEM, gconf_callback, (void *)priv, NULL, &error);
	if (error != NULL) {
		WN_ERR("Could not monitor gconf system wide key for changes");
		g_clear_error(&error);
		goto err;
	}

	if (setup_wireguard_dbus(priv)) {
		WN_ERR("Could not request dbus interface");
		goto err;
	}

	open_netlink_listener(priv);

	network_api->network_destruct = wireguard_network_destruct;
	network_api->child_exit = wireguard_child_exit;

	priv->watch_cb = watch_fn;
	priv->watch_cb_token = watch_fn_token;
	priv->close_cb = close_fn;

	network_api->private = priv;

#if 0
	priv->status_change_fn = status_change_fn;
	priv->renew_fn = renew_fn;
#endif

	return TRUE;

 err:
	if (priv->gconf_client) {
		g_object_unref(priv->gconf_client);
		priv->gconf_client = NULL;
	}

	g_free(priv);

	return FALSE;
}
