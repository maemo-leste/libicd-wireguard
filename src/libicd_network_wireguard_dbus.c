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
#include <glib.h>

#include "libicd_wireguard.h"
#include "dbus_wireguard.h"
#include "libicd_network_wireguard.h"

static DBusHandlerResult start_reply(dbus_int32_t return_code, DBusMessage * reply)
{
	dbus_message_append_args(reply, DBUS_TYPE_INT32, &return_code, DBUS_TYPE_INVALID);

	if (icd_dbus_send_system_msg(reply) == FALSE) {
		WN_WARN("icd_dbus_send_system_msg failed");
	}

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult start_callback(DBusConnection * connection, DBusMessage * message, void *user_data)
{
	network_wireguard_private *priv = user_data;
	DBusError error;
	const char *config;

	DBusMessage *reply = dbus_message_new_method_return(message);
	if (!reply) {
		WN_WARN("icd_dbus_send_system_msg failed");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!priv->state.service_provider_mode) {
		/* We do not accept dbus commands from non-providers */

		return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_REFUSED, reply);
	}

	/* We are in provider mode */

	/* Wireguard already running? */
	if (priv->state.wireguard_running == TRUE) {
		return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_ALREADY_RUNNING, reply);
	}

	dbus_error_init(&error);
	if (dbus_message_get_args(message, &error, DBUS_TYPE_STRING, &config, DBUS_TYPE_INVALID) == FALSE) {
		WN_WARN("start_callback received invalid arguments: %s", error.message);
		dbus_error_free(&error);

		return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_INVALID_ARGS, reply);
	}

	if (!config_is_known(config)) {
		return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_INVALID_CONFIG, reply);
	}

	/* Actually start Tor */
	network_wireguard_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
	new_state.active_config = g_strdup(config);
	wireguard_state_change(priv, NULL, new_state, EVENT_SOURCE_DBUS_CALL_START);

	if (priv->state.dbus_failed_to_start) {
		priv->state.dbus_failed_to_start = FALSE;
		return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_FAILED, reply);
	}

	return start_reply(WIREGUARD_DBUS_METHOD_START_RESULT_OK, reply);
}

DBusHandlerResult stop_callback(DBusConnection * connection, DBusMessage * message, void *user_data)
{
	network_wireguard_private *priv = user_data;

	DBusMessage *reply = dbus_message_new_method_return(message);
	if (!reply) {
		WN_WARN("icd_dbus_send_system_msg failed");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!priv->state.service_provider_mode) {
		/* We do not accept dbus commands from non-providers */

		return start_reply(WIREGUARD_DBUS_METHOD_STOP_RESULT_REFUSED, reply);
	}

	/* Wireguard not running? */
	if (priv->state.wireguard_running == FALSE) {
		return start_reply(WIREGUARD_DBUS_METHOD_STOP_RESULT_NOT_RUNNING, reply);
	}

	/* Actually stop Wireguard */
	network_wireguard_state new_state;
	memcpy(&new_state, &priv->state, sizeof(network_wireguard_state));
	wireguard_state_change(priv, NULL, new_state, EVENT_SOURCE_DBUS_CALL_STOP);

	return start_reply(WIREGUARD_DBUS_METHOD_STOP_RESULT_OK, reply);
}

DBusHandlerResult getstatus_callback(DBusConnection * connection, DBusMessage * message, void *user_data)
{
	const char *state = NULL;
	const char *mode = NULL;
	network_wireguard_private *priv = user_data;

	DBusMessage *reply = dbus_message_new_method_return(message);
	if (!reply) {
		WN_WARN("icd_dbus_send_system_msg failed");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* TODO: DRY this */
	if (!priv->state.wireguard_running) {
		state = ICD_WIREGUARD_SIGNALS_STATUS_STATE_STOPPED;
	} else {
		if (priv->state.wg_quick_running) {
			state = ICD_WIREGUARD_SIGNALS_STATUS_STATE_STARTED;
		} else {
			state = ICD_WIREGUARD_SIGNALS_STATUS_STATE_CONNECTED;
		}
	}

	if (!priv->state.service_provider_mode) {
		mode = ICD_WIREGUARD_SIGNALS_STATUS_MODE_NORMAL;
	} else {
		mode = ICD_WIREGUARD_SIGNALS_STATUS_MODE_PROVIDER;
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &state, DBUS_TYPE_STRING, &mode, DBUS_TYPE_INVALID);

	if (icd_dbus_send_system_msg(reply) == FALSE) {
		WN_WARN("icd_dbus_send_system_msg failed");
		dbus_message_unref(reply);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

void emit_status_signal(network_wireguard_state state)
{
	const char *status = NULL;
	const char *mode = NULL;
	DBusMessage *msg = NULL;

	msg = dbus_message_new_signal(ICD_WIREGUARD_DBUS_PATH, ICD_WIREGUARD_DBUS_INTERFACE, "StatusChanged");
	if (msg == NULL) {
		WN_WARN("Could not construct dbus message for StatusChanged signal");
		return;
	}

	/* TODO: DRY this */
	if (!state.wireguard_running) {
		status = ICD_WIREGUARD_SIGNALS_STATUS_STATE_STOPPED;
	} else {
		if (state.wg_quick_running) {
			status = ICD_WIREGUARD_SIGNALS_STATUS_STATE_STARTED;
		} else {
			status = ICD_WIREGUARD_SIGNALS_STATUS_STATE_CONNECTED;
		}
	}

	if (!state.service_provider_mode) {
		mode = ICD_WIREGUARD_SIGNALS_STATUS_MODE_NORMAL;
	} else {
		mode = ICD_WIREGUARD_SIGNALS_STATUS_MODE_PROVIDER;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &status, DBUS_TYPE_STRING, &mode, DBUS_TYPE_INVALID);

	icd_dbus_send_system_msg(msg);

	dbus_message_unref(msg);
}
