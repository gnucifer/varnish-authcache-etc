#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <nettle/md5.h>
#include <syslog.h>

#define DRUPAL_AUTHCACHE_SALT "test"
#define DRUPAL_AUTHCACHE_SEPARATOR "."

/*TODO: Have I managed my memory correctly? */
const char *
drupal_authcache_hash(const char *cookie_header, const char *client_ip) {
	char *cookie_header_work;
	char *cookie_header_pos;
	char *cookie;
	char *cookie_pos;
	char *drupal_ac_hash = NULL;
	char *drupal_ac_sum = NULL;
	char *drupal_ac_expire = NULL;
	struct tm tm_expire = {0,0,0,0,0,0,0,0,0};

	struct md5_ctx ctx;
	uint8_t digest[MD5_DIGEST_SIZE];

	cookie_header_work = strdup(cookie_header);

	/*TODO: "; " is safe, wut? */
	for(cookie = strtok_r(cookie_header_work, "; ", &cookie_header_pos);
			cookie != NULL;
			cookie = strtok_r(NULL, "; ", &cookie_header_pos)) /*TODO: This looks pretty unsafe, what if more whitespace after ; or none? */
	{
		if(
				!strncmp(cookie, "DRUPAL_AC=", 10) &&
				(drupal_ac_hash = strtok_r(&cookie[10], DRUPAL_AUTHCACHE_SEPARATOR, &cookie_pos)) &&
				(drupal_ac_expire = strtok_r(NULL, DRUPAL_AUTHCACHE_SEPARATOR, &cookie_pos)) &&
				(drupal_ac_sum = strtok_r(NULL, DRUPAL_AUTHCACHE_SEPARATOR, &cookie_pos))
			) {
			break;
		}
	}

	
	/*check so we don't get buffer overflows from to short validation digests, and that a correclty formatted cookie was sent
	also bail out if cookie has expired
	storing an int in char we lose 4 bit per byte */
	if(!drupal_ac_sum || strlen(drupal_ac_sum) != MD5_DIGEST_SIZE*2) {
		free(cookie_header_work);
		openlog("drupal_authcache", 0, 0);
		syslog(LOG_MAKEPRI(LOG_USER, LOG_NOTICE), "return empty"); 
		closelog();
		return "";
	}

	/*also bail out if cookie has expired or expire value tampered with */
	
	/*TODO: Null pointer comparison shit */
	/*"%s" is a GNU-extension */
	strptime(drupal_ac_expire, "%s", &tm_expire); 
	
	if(mktime(&tm_expire) < time(NULL)) {
		free(cookie_header_work);

		openlog("drupal_authcache", 0, 0);
		syslog(LOG_MAKEPRI(LOG_USER, LOG_NOTICE), "wrong time"); 
		closelog();
		
		return "";
	}

	openlog("drupal_authcache", 0, 0);
	syslog(LOG_MAKEPRI(LOG_USER, LOG_NOTICE), client_ip);

	char *validation_buffer;
	int i;

	/*printf("ip: %s, salt: %s, hash: %s\n", client_ip, DRUPAL_AUTHCACHE_SALT, drupal_ac_hash); */
	/*validate */
	
	md5_init(&ctx);
	md5_update(&ctx, strlen(client_ip), (uint8_t*)client_ip);
	md5_update(&ctx, strlen(DRUPAL_AUTHCACHE_SALT), (uint8_t*)DRUPAL_AUTHCACHE_SALT);
	md5_update(&ctx, strlen(drupal_ac_hash), (uint8_t*)drupal_ac_hash);
	md5_update(&ctx, strlen(drupal_ac_expire), (uint8_t*)drupal_ac_expire);
	md5_digest(&ctx, MD5_DIGEST_SIZE, digest);


	syslog(LOG_MAKEPRI(LOG_USER, LOG_NOTICE), "test"); 

	validation_buffer = malloc(2 * sizeof(validation_buffer));

	for(i = 0; i < MD5_DIGEST_SIZE; i++) {
		
		sprintf(validation_buffer, "%02x", digest[i]);

		if(strncmp(validation_buffer, (drupal_ac_sum + i*2), 2)){
			drupal_ac_hash = "";
			syslog(LOG_MAKEPRI(LOG_USER, LOG_NOTICE), "break"); 
			break;
		}
	}
	closelog();
	free(validation_buffer);
	drupal_ac_hash = strdup(drupal_ac_hash);
	free(cookie_header_work);
	/*return hash, empty string if validation failed */


	return drupal_ac_hash;
}

int
main(int argc, char **argv)
{
	char test[] = "OTHER_COOKIE=sefsefsefs; DRUPAL_AC=c81e728d9d4c2f636f067f89cc14862c.1286650469.3cbd88557de1d77292cacddb31774cb9; OTHER_OTHER_COOKIE=sfsefsefsefsefsef;";
	printf("%s\n", drupal_authcache_hash(test, "127.0.0.1"));
	return EXIT_SUCCESS;  
}

