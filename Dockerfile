FROM debian:jessie

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Debian Jessie (oldoldstable) has OpenSSL 1.0.1 with SSLv3 compiled in
RUN echo "deb http://archive.debian.org/debian/ jessie main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security/ jessie/updates main" >> /etc/apt/sources.list && \
    apt-get update && apt-get install -y --allow-unauthenticated \
    apache2 \
    openssl \
    libapache2-mod-php5 \
    php5 \
    && rm -rf /var/lib/apt/lists/*

# Enable SSL and PHP modules
RUN a2enmod ssl
RUN a2enmod php5

# Create directory for SSL certificates
RUN mkdir -p /etc/apache2/ssl

# Generate self-signed certificate
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/apache.key \
    -out /etc/apache2/ssl/apache.crt \
    -subj "/C=US/ST=Test/L=Test/O=VulnerableServer/CN=vulnerable.local"

# Copy vulnerable SSL configuration
COPY ssl-vulnerable.conf /etc/apache2/sites-available/default-ssl.conf

# Enable SSL site
RUN a2ensite default-ssl

# Copy web application
COPY www/ /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

# Expose HTTPS port
EXPOSE 443

# Start Apache in foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
