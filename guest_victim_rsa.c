#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

static const char kFixedRsaPem[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpQIBAAKCAQEAwTLPzBPKghN/suvqFk9XjsOVxyL15zdH/5f72mBgM+0zYQTl\n"
    "rGvJ4Ix71gJxStclVUDICQ5PSnBeN82qtYY5QqwlPXD/aCDEH50QjAB6TCX5shrJ\n"
    "HUC90osDX3aHFRYa6TciCrbmn2umBYodra6TDRctbFZignnsCbcYLwuaJshceCu7\n"
    "oWEA4O424BjVmlUlTarpbCba8TsSnhU9hVJfUksaecybcQanbjAfofvpl3V88tY8\n"
    "haSEYnbQdY2LcZaBo6bvUNG/nyeRDDmFS+DZrRij30vhhkG0Z0ra9rWU4JZ2slXo\n"
    "B2MqRCGzRMfR4VVKNH9gTwUgBzuyajfAyloZmwIDAQABAoIBAFM7u1duDVhF40Wn\n"
    "qpWLACtS6vO8hZlj8SJWDZyS2c91OSXqsLI8S+BwVaepLLrz/rMAck2oexOUXpsH\n"
    "Aa0r0v584JxcUsS/HQ+LoMXYLNgiojUPoiZ2rnEHD+BwVZkJiXWBGarpCmmTPJb1\n"
    "XnzlkZfZrOmYO99/fGfhGEuoYXSkLFiNmkHHe4Bfl+IUdEvp6kIbF9SkgrwY3M53\n"
    "5yJhgWRss+z8usVeRWUfpZeoD4wfwXWy1v2rrk8RXdVlI2CV9iIRyN22y6A82LD+\n"
    "uw3CMiihs+amYJwa6oXTG0EJddN+UYqhPMk9lIDlsk+PAcsDszd1unbFBU9E1NDg\n"
    "ZYTi/5kCgYEA0AAz4pHdXHjjVd8LDzbbPMlKYwmo/wstzOb9Ho9gneVs32ALer3Z\n"
    "NgVeg+6P83PDQudMk7EVFkqlJVe4KmOZTPhpEUxUOk4W3j+xJ8QkQavXXlr5/p2G\n"
    "1T4w7u2Rtht9BBYQe8Cbl/djsA12NP/dddlbH5i8pGKvPxoPunhGj/kCgYEA7cgm\n"
    "5drn4Qd3Hz4P43/G1Jn2Ux0amsB39GCcravnEVZTrRHxHLECmEoTtpKNgLGlKkKN\n"
    "l8MBUeEKJIQFwySim2kTmQzNn7pyHl2mQ1l+PcXAARAdnPsKVmy2TZOLc7L1r/wi\n"
    "GoCKpzVTOZoJXB/k1sn+iiP5kqW/rFnqOuNXgzMCgYEAxqNa6YX5i4UbPfeavTXb\n"
    "G2r0Mi6YiLCpVaRGmHe+giwG1DAJ5ncFx9RK1d3u9UVZdTwk4mrbw4UXv9jM1RZ2\n"
    "4Y3d8Roe2euXZToYOezT3y93pvFlC2ZuzJju7E5OuEX6FvvnU/e13+Pu/MNuXuD3\n"
    "IsOnhT488RQZXj7KRH72jCkCgYEA0B0ubl96M+pkyGN5ZJShYdKfVX9Tmb57PtiQ\n"
    "STD7vKDh+8iIT6RdsQyk1FbQoqLY/HPjmcCDlzZvuiYTJQkbiQoerQYXsoVs/Ebb\n"
    "Dnd1lntN4aBJSuwt0Ba2OI+6rjkj8DOtZaS7tj1l6jR3nLoNgDCrKBz0gvWvHRpV\n"
    "d9Ui8yECgYEAngpGSMdMHiwWc1l3j0C6BXmGWfI/22ekdlWvMNkqlMS8wA8dGpX5\n"
    "nO+rSV1qQkKe38ilVnn9RLYHyUXjjAT0eymblWtuoik+JV/F2lZ75fk8k6+/qjRd\n"
    "fF4H1ag2KpXRWN3KrXgldLtSd2ETXglFX5ZJeBMNW6YhhGt8FbZmwAk=\n"
    "-----END RSA PRIVATE KEY-----\n";

static ssize_t readn(int fd, void *buf, size_t n) {
  uint8_t *p = (uint8_t *)buf;
  size_t done = 0;
  while (done < n) {
    ssize_t r = read(fd, p + done, n - done);
    if (r == 0)
      return (ssize_t)done;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    done += (size_t)r;
  }
  return (ssize_t)done;
}

static ssize_t writen(int fd, const void *buf, size_t n) {
  const uint8_t *p = (const uint8_t *)buf;
  size_t done = 0;
  while (done < n) {
    ssize_t w = write(fd, p + done, n - done);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    done += (size_t)w;
  }
  return (ssize_t)done;
}

static int parse_port(int argc, char **argv) {
  int port = 9001;
  for (int i = 1; i + 1 < argc; i++) {
    if (strcmp(argv[i], "--port") == 0) {
      port = atoi(argv[i + 1]);
      i++;
    }
  }
  if (port <= 0 || port > 65535)
    port = 9001;
  return port;
}

static int setup_listener(int port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  struct sockaddr_in addr;

  if (fd < 0)
    return -1;
  (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons((uint16_t)port);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  if (listen(fd, 64) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static RSA *load_fixed_rsa_key(void) {
  BIO *bio = BIO_new_mem_buf(kFixedRsaPem, -1);
  RSA *rsa = NULL;
  if (!bio)
    return NULL;
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!rsa)
    return NULL;

  /* Keep path closer to classic variable-time private operation. */
  RSA_blinding_off(rsa);
  RSA_set_flags(rsa, RSA_FLAG_NO_BLINDING);
  return rsa;
}

int main(int argc, char **argv) {
  int port = parse_port(argc, argv);
  int lfd = -1;
  RSA *rsa = load_fixed_rsa_key();

  if (!rsa) {
    fprintf(stderr, "victim_rsa: load fixed key failed\n");
    return 1;
  }

  if (RSA_size(rsa) != 256) {
    fprintf(stderr, "victim_rsa: unexpected key size: %d\n", RSA_size(rsa));
    RSA_free(rsa);
    return 1;
  }

  lfd = setup_listener(port);
  if (lfd < 0) {
    fprintf(stderr, "victim_rsa: listen failed on %d: %s\n", port,
            strerror(errno));
    RSA_free(rsa);
    return 1;
  }

  fprintf(stderr, "victim_rsa: listening on 0.0.0.0:%d\n", port);
  fflush(stderr);

  for (;;) {
    int cfd = accept(lfd, NULL, NULL);
    uint8_t hash32[32];
    uint8_t sig[256];
    int outlen = 0;

    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      usleep(1000);
      continue;
    }

    if (readn(cfd, hash32, sizeof(hash32)) == (ssize_t)sizeof(hash32)) {
      outlen = RSA_private_encrypt((int)sizeof(hash32), hash32, sig, rsa,
                                   RSA_PKCS1_PADDING);
      if (outlen == (int)sizeof(sig))
        (void)writen(cfd, sig, sizeof(sig));
    }
    close(cfd);
  }
}

