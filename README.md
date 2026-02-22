# UniFi Network Monitoring Stack

Docker Compose stack for monitoring UniFi networks with UnPoller, Prometheus, and Grafana.

## Quick Start

1. **Clone and configure**

   ```bash
   git clone https://github.com/timothystewart6/unpoller-unifi.git   
   cd unpoller-UniFi
   ```

2. **Edit UniFi credentials**

   Update `unpoller/.env` with your controller details, it's advised to create a dedicated local UniFi account that has read only access to your Network controller:

   ```env
    UP_UniFi_CONTROLLER_0_URL=https://192.168.10.1
    UP_UniFi_CONTROLLER_0_USER=unpoller
    UP_UniFi_CONTROLLER_0_PASS=password123
    UP_UniFi_CONTROLLER_0_SITE=default
   ```

   Update Grafana admin credentials in `grafana/.env`:

   ```env
   GF_SECURITY_ADMIN_USER=admin
   GF_SECURITY_ADMIN_PASSWORD=admin123
   ```

   Optionally update timezone in `dozzle/.env`, `grafana/.env`, `prometheus/.env`, `unpoller/.env`:

   ```env
   TZ=Your/Timezone
   ```

3. **Start the stack**

   ```bash
   docker-compose up -d
   ```

## Access

| Service | URL |
| ------- | --- |
| Grafana | <http://localhost:3000> |
| Prometheus | <http://localhost:9090> |
| Dozzle (logs) | <http://localhost:8080> |

**Grafana default login**: admin/admin123 (change in `grafana/.env`)

## What's Included

- Pre-configured environment files for all services
- Grafana dashboards for UniFi devices (Access Points, Switches, Gateway, Clients, DPI, Sites, PDU)
- Prometheus data source auto-provisioned
- Log viewer with Dozzle

## Resources

- **📖 Detailed Guide**: [UniFi Observability with UnPoller, Prometheus, and Grafana](https://technotim.com/posts/unpoller-unifi-metrics/)
- **🎥 Video Tutorial**: [UniFi Observability Done Right (Unpoller + Grafana Walkthrough)](https://www.youtube.com/watch?v=cVCPKTHEnI8)

## Troubleshooting

- Check logs: `docker-compose logs [service-name]` or use Dozzle at <http://localhost:8080>
- Verify UniFi controller accessibility from Docker network
- Ensure a local UniFi account has been created with read-only/view-only network controller access
- For 429 errors, increase scrape interval in `prometheus/config/prometheus.yml`

## Acknowledgments

This stack is built using these excellent open-source projects:

- **[UnPoller](https://github.com/unpoller/unpoller)** - Polls UniFi controllers for device and client metrics
- **[Prometheus](https://github.com/prometheus/prometheus)** - Systems monitoring and alerting toolkit
- **[Grafana](https://github.com/grafana/grafana)** - Open source analytics and interactive visualization web application
- **[Dozzle](https://github.com/amir20/dozzle)** - Real-time log viewer for Docker containers

Special thanks to the maintainers and contributors of these projects for making UniFi network monitoring accessible and powerful.
