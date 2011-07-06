# This block of inline C loads the library
C{
  #include <stdlib.h>
  #include <stdio.h>
	#include <string.h>

	#include <dlfcn.h>
static const char* (*drupal_authcache_hash)(const char *cookie_header, const char* client_ip) = NULL;

__attribute__((constructor)) void
drupal_authcache_load()
{
	const char *symbol_name = "drupal_authcache_hash";
	const char *plugin_name = "/etc/varnish/drupal_authcache.so";
	void* handle = NULL;
	
	handle = dlopen( plugin_name, RTLD_NOW );
	if (handle != NULL) {
		drupal_authcache_hash = dlsym( handle, symbol_name );
		if (drupal_authcache_hash == NULL)
			fprintf( stderr, "\nError: Could not load Drupal Authcache plugin:\n%s\n\n", dlerror() );
		else
			printf( "Drupal Authcache plugin loaded successfully.\n");
	}
	else
		fprintf( stderr, "\nError: Could not load Drupal Authcache plugin:\n%s\n\n", dlerror() );
}
}C


sub drupal_authcache_process {
C{
	if (drupal_authcache_hash) {
		char *cookie_hdr = VRT_GetHdr(sp, HDR_REQ, "\007Cookie:");
		if(strstr(cookie_hdr, "DRUPAL_AC=")) { 
			char *auth_hash = (char*) (*drupal_authcache_hash)(cookie_hdr, VRT_IP_string(sp, VRT_r_client_ip(sp)));
			if(strlen(auth_hash)) {
				/* VRT_l_req_hash(sp, auth_hash); */
				VRT_SetHdr(sp, HDR_REQ, "\021X-Drupal-AC-Hash:", auth_hash, vrt_magic_string_end);
			}
		}
	}
}C
}

sub vcl_recv {
	#TODO: use equals instead
	if (req.url ~ "^/logout|^/user|^/node/(add|edit)" ) {
		return (pass);
	}
}

sub vcl_fetch {
	if(beresp.http.pragma ~ "no-cache") {
		return (pass);
	}
}
