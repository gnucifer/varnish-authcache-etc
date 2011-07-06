LDLIBS=-lnettle

drupal_authcache.so:	drupal_authcache.c
	gcc -Wall -DDEBUG -shared -fPIC $< -o $@ $(LDLIBS)

test:	drupal_authcache_test.c drupal_authcache.so
	gcc $< -o drupal_authcache_test -ldl
	LD_LIBRARY_PATH=$$PWD ./drupal_authcache_test

clean:
	rm -f drupal_authcache.so
