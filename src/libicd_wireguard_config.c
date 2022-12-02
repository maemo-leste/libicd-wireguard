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

#include <stdio.h>

#include <glib.h>
#include <gconf/gconf-client.h>

#include "libicd_network_wireguard.h"

gboolean config_is_known(const char *config_name)
{
	GConfClient *gconf_client;
	GSList *providers = NULL, *l = NULL;
	gboolean match = FALSE;

	gconf_client = gconf_client_get_default();

	providers = gconf_client_get_list(gconf_client, GC_ICD_WIREGUARD_AVAILABLE_IDS, GCONF_VALUE_STRING, NULL);
	for (l = providers; l; l = l->next) {
		if (!strcmp(l->data, config_name)) {
			match = TRUE;
			break;
		}
	}
	g_slist_free_full(providers, g_free);
	g_object_unref(gconf_client);

	return match;
}

gboolean network_is_wireguard_provider(const char *network_id, char **ret_gconf_service_id)
{
	GConfClient *gconf_client;
	gchar *iap_gconf_key;
	char *gconf_service_type = NULL;
	char *gconf_service_id = NULL;
	gboolean service_id_known = FALSE;
	gboolean match = FALSE;

	gconf_client = gconf_client_get_default();

	iap_gconf_key = g_strdup_printf("/system/osso/connectivity/IAP/%s/service_type", network_id);
	gconf_service_type = gconf_client_get_string(gconf_client, iap_gconf_key, NULL);
	g_free(iap_gconf_key);

	iap_gconf_key = g_strdup_printf("/system/osso/connectivity/IAP/%s/service_id", network_id);
	gconf_service_id = gconf_client_get_string(gconf_client, iap_gconf_key, NULL);
	g_free(iap_gconf_key);
	g_object_unref(gconf_client);

	service_id_known = gconf_service_id && config_is_known(gconf_service_id);

	if (ret_gconf_service_id)
		*ret_gconf_service_id = g_strdup(gconf_service_id);

	match = service_id_known && (g_strcmp0(WIREGUARD_PROVIDER_TYPE, gconf_service_type) == 0);

	if (gconf_service_type) {
		g_free(gconf_service_type);
	}

	if (gconf_service_id) {
		g_free(gconf_service_id);
	}

	return match;
}

gboolean get_system_wide_enabled(void)
{
	GConfClient *gconf;
	gboolean enabled = FALSE;

	gconf = gconf_client_get_default();

	enabled = gconf_client_get_bool(gconf, GC_WIREGUARD_SYSTEM, NULL);

	g_object_unref(gconf);

	return enabled;
}

char *get_active_config(void)
{
	GConfClient *gconf;
	char *active_config = NULL;

	gconf = gconf_client_get_default();

	active_config = gconf_client_get_string(gconf, GC_WIREGUARD_ACTIVE, NULL);

	g_object_unref(gconf);

	return active_config;
}

char *generate_config(const char *config_name)
{
	GConfClient *gconf;
	gchar *config = NULL;
	gchar *address, *dns, *privatekey, *configoverride;
	GSList *peers, *iter;

	gconf = gconf_client_get_default();

	gchar *cfgpath = g_strjoin("/", GC_WIREGUARD, config_name, NULL);

	gchar *gc_configoverride = g_strjoin("/", cfgpath, GC_CONFIG_FILE_OVERRIDE, NULL);
	configoverride = gconf_client_get_string(gconf, gc_configoverride, NULL);
	g_free(gc_configoverride);

	if (configoverride) {
		GError *error = NULL;
		char *config_contents = NULL;
		g_file_get_contents(configoverride, &config_contents, NULL, &error);
		if (error != NULL) {
			WN_WARN("Unable to read config override: %s\n", error->message);
			g_clear_error(&error);
			return NULL;
		}

		return config_contents;
	}

	/* Interface configuration */
	gchar *gc_privatekey = g_strjoin("/", cfgpath, GC_PRIVATEKEY, NULL);
	privatekey = gconf_client_get_string(gconf, gc_privatekey, NULL);
	g_free(gc_privatekey);

	gchar *gc_address = g_strjoin("/", cfgpath, GC_ADDRESS, NULL);
	address = gconf_client_get_string(gconf, gc_address, NULL);
	g_free(gc_address);

	gchar *gc_dns = g_strjoin("/", cfgpath, GC_DNS, NULL);
	dns = gconf_client_get_string(gconf, gc_dns, NULL);
	g_free(gc_dns);

	if (privatekey == NULL || address == NULL)
		goto out;

	config = g_strconcat(
			 "[Interface]"
			 "\nPrivateKey = ", privatekey,
			 "\nAddress = ", address,
			 NULL);
	if (dns) {
		gchar *tmp = config;

		config = g_strconcat(tmp, "\nDNS = ", dns, "\n", NULL);
		g_free(tmp);
	}

	/* Peers configuration */
	gchar *gc_peers = g_strjoin("/", cfgpath, GC_PEERS, NULL);
	peers = gconf_client_all_dirs(gconf, gc_peers, NULL);
	g_free(gc_peers);

	if (peers == NULL)
		goto out;

	for (iter = peers; iter; iter = iter->next) {
		gchar *gc_peer_ips = g_strjoin("/", iter->data, GC_PEER_IPS, NULL);
		gchar *peer_ips = gconf_client_get_string(gconf, gc_peer_ips, NULL);
		gchar *tmp;

		g_free(gc_peer_ips);

		gchar *gc_endpoint = g_strjoin("/", iter->data, GC_PEER_ENDPOINT, NULL);
		gchar *endpoint = gconf_client_get_string(gconf, gc_endpoint, NULL);
		g_free(gc_endpoint);

		gchar *gc_pubkey = g_strjoin("/", iter->data, GC_PEER_PUBKEY, NULL);
		gchar *pubkey = gconf_client_get_string(gconf, gc_pubkey, NULL);
		g_free(gc_pubkey);

		g_free(iter->data);

		if (peer_ips == NULL || endpoint == NULL || pubkey == NULL)
			continue;

		tmp = config;
		config = g_strconcat(
				 tmp, "\n[Peer]",
				 "\nPublicKey = ", pubkey,
				 "\nEndPoint = ", endpoint,
				 "\nAllowedIPs = ", peer_ips, "\n",
				 NULL);
		g_free(tmp);
	}

	g_slist_free(iter);
	g_slist_free(peers);

 out:
	g_free(cfgpath);
	g_object_unref(gconf);

	return config;
}
