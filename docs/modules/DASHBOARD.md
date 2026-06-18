# Dashboard Module Documentation

## Overview

The Next.js dashboard provides a beautiful, modern web interface for monitoring DLP events, managing policies, and administering the system. It's accessible via host IP address, making it available across your network.

## Key Features

- Real-time event monitoring
- Interactive charts and visualizations
- Policy management interface
- User administration
- Compliance reporting
- Role-based access control
- Responsive design (desktop, tablet, mobile)
- Dark mode support (optional)

## Technology Stack

- **Framework**: Next.js 14
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **State Management**: Zustand
- **Data Fetching**: React Query (TanStack Query)
- **Charts**: Recharts
- **Icons**: Lucide React

## Directory Structure

```
dashboard/
├── src/
│   ├── app/                    # Next.js app directory
│   │   ├── layout.tsx          # Root layout
│   │   ├── page.tsx            # Login page
│   │   ├── globals.css         # Global styles
│   │   └── dashboard/          # Dashboard pages
│   │       ├── page.tsx        # Main dashboard
│   │       ├── events/         # Events page
│   │       ├── policies/       # Policies page
│   │       └── users/          # Users page
│   ├── components/             # React components
│   │   ├── auth/               # Authentication components
│   │   │   └── LoginForm.tsx
│   │   ├── layout/             # Layout components
│   │   │   └── DashboardLayout.tsx
│   │   ├── dashboard/          # Dashboard widgets
│   │   │   ├── StatsCard.tsx
│   │   │   ├── EventsTimeline.tsx
│   │   │   ├── RecentEvents.tsx
│   │   │   ├── TopViolations.tsx
│   │   │   └── TopUsers.tsx
│   │   └── Providers.tsx       # App providers
│   ├── lib/                    # Utilities
│   │   ├── api.ts              # API client
│   │   └── store/              # State management
│   │       └── auth.ts         # Auth store
│   └── hooks/                  # Custom hooks
├── public/                     # Static assets
├── package.json                # Dependencies
├── next.config.js              # Next.js configuration
├── tailwind.config.js          # Tailwind configuration
├── tsconfig.json               # TypeScript configuration
├── Dockerfile                  # Docker configuration
└── .env.local                  # Environment variables
```

## Installation

### Prerequisites

- Node.js 18 or higher
- npm or yarn

### Local Development

```bash
# Navigate to dashboard directory
cd dashboard

# Install dependencies
npm install

# Set up environment
cp .env.local.example .env.local
# Edit .env.local with your API URL

# Start development server
npm run dev

# Dashboard will be available at http://localhost:3000
# And accessible via host IP: http://<your-ip>:3000
```

### Production Build

```bash
# Build for production
npm run build

# Start production server
npm start

# Production server will listen on 0.0.0.0:3000
```

### Docker Deployment

```bash
# Build image
docker build -t seceoknight-dashboard .

# Run container
docker run -d \
  -p 3000:3000 \
  -e NEXT_PUBLIC_API_URL=http://<your-api-host>:8000/api/v1 \
  --name seceoknight-dashboard \
  seceoknight-dashboard
```

## Configuration

### Environment Variables

Create `.env.local` file:

```bash
# API Configuration
# IMPORTANT: Replace localhost with your server's IP address
NEXT_PUBLIC_API_URL=https://YOUR_SERVER_IP/api/v1

# Application
NEXT_PUBLIC_APP_NAME=SeceoKnight DLP
NEXT_PUBLIC_APP_VERSION=1.0.0

# Features
NEXT_PUBLIC_ENABLE_REAL_TIME_UPDATES=true
NEXT_PUBLIC_ENABLE_NOTIFICATIONS=true

# Refresh Intervals (milliseconds)
NEXT_PUBLIC_DASHBOARD_REFRESH_INTERVAL=30000
NEXT_PUBLIC_EVENTS_REFRESH_INTERVAL=10000
```

### Accessing via Host IP

The dashboard is configured to bind to `0.0.0.0`, making it accessible via:

1. **Localhost**: `http://localhost:3000`
2. **Host IP**: `https://YOUR_SERVER_IP` (replace with your IP)
3. **Hostname**: `http://hostname:3000`

To find your host IP:

```bash
# Linux/macOS
hostname -I | awk '{print $1}'

# Windows
ipconfig | findstr IPv4
```

## Default Credentials

**Email**: `admin@seceoknight.local`
**Password**: `ChangeMe123!`

**IMPORTANT**: Change the default password immediately after first login!

## Features

### 1. Dashboard Overview

- **Real-time Statistics**: Events, blocks, alerts, active policies
- **Timeline Chart**: Visualize event trends over time
- **Recent Events**: List of latest DLP events
- **Top Violations**: Most triggered policies
- **Top Users**: Users with most events

### 2. Event Management

- **Event List**: Filterable and sortable event list
- **Event Details**: Detailed view of each event
- **Severity Filters**: Filter by critical, high, medium, low
- **Source Filters**: Filter by endpoint, network, cloud
- **Search**: Search by user, file path, destination
- **Export**: Export events to CSV/PDF

### 3. Policy Management

- **Policy List**: View all DLP policies
- **Create Policy**: Visual policy builder
- **Edit Policy**: Modify existing policies
- **Enable/Disable**: Toggle policy status
- **Priority Management**: Set policy execution order
- **Policy Testing**: Test policies against sample data

### 4. User Management (Admin Only)

- **User List**: View all users
- **Add User**: Create new users
- **Edit User**: Modify user details and roles
- **Role Assignment**: Assign admin, analyst, or viewer roles
- **Activity Tracking**: View user activity logs

### 5. Compliance Reporting

- **GDPR Reports**: GDPR compliance status
- **HIPAA Reports**: HIPAA compliance status
- **PCI-DSS Reports**: PCI-DSS compliance status
- **Audit Trail**: Complete audit log
- **Export Reports**: Download compliance reports

## User Roles

### Admin
- Full system access
- User management
- Policy creation/modification
- System configuration
- Compliance reporting

### Analyst
- View all events
- Create/modify policies
- Acknowledge alerts
- Generate reports

### Viewer
- View events (read-only)
- View policies (read-only)
- View reports (read-only)

## UI Components

### StatsCard

Display key metrics with icons and trends:

```typescript
<StatsCard
  title="Total Events (24h)"
  value="1,247"
  change="+12%"
  icon={Shield}
  color="blue"
/>
```

### EventsTimeline

Interactive chart showing event trends:

```typescript
<EventsTimeline />
```

### RecentEvents

List of recent DLP events:

```typescript
<RecentEvents events={events} />
```

## API Integration

The dashboard communicates with the FastAPI backend via REST API:

```typescript
// API client (src/lib/api.ts)
import apiClient from '@/lib/api'

// Get dashboard overview
const overview = await api.getDashboardOverview()

// Get events
const events = await api.getEvents({ severity: 'critical' })

// Create policy
const policy = await api.createPolicy(policyData)
```

## State Management

Using Zustand for authentication state:

```typescript
// src/lib/store/auth.ts
const { isAuthenticated, user, login, logout } = useAuthStore()

// Login
await login(email, password)

// Logout
logout()
```

## Styling

### Tailwind CSS

Custom theme configuration in `tailwind.config.js`:

```javascript
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: { /* blue shades */ },
        danger: { /* red shades */ },
        success: { /* green shades */ },
        warning: { /* yellow shades */ },
      },
    },
  },
}
```

### Custom Components

All components follow consistent styling:
- Rounded corners (`rounded-lg`)
- Shadows for depth (`shadow-md`)
- Hover effects (`hover:shadow-lg`)
- Transitions (`transition-all`)
- Responsive design (`md:`, `lg:` breakpoints)

## Performance Optimization

### Data Fetching

- React Query for efficient data fetching
- Automatic caching
- Background refetching
- Optimistic updates

### Code Splitting

- Automatic code splitting by Next.js
- Dynamic imports for large components
- Image optimization

### Production Build

```bash
# Build optimized production bundle
npm run build

# Analyze bundle size
npm run analyze
```

## Real-Time Updates

Events are automatically refreshed:

```typescript
const { data } = useQuery({
  queryKey: ['dashboard-overview'],
  queryFn: api.getDashboardOverview,
  refetchInterval: 30000, // Refresh every 30 seconds
})
```

## Troubleshooting

### Can't access via host IP

1. Check firewall allows port 3000
2. Verify Next.js is bound to 0.0.0.0
3. Check network connectivity

```bash
# Test from another machine
curl http://<host-ip>:3000
```

### API connection errors

1. Verify API URL in `.env.local`
2. Check CORS settings on server
3. Ensure API is running

```bash
# Test API
curl http://<api-host>:8000/health
```

### Login fails

1. Check default credentials
2. Verify API authentication endpoint
3. Check browser console for errors

### Slow performance

1. Check network latency
2. Reduce refresh intervals
3. Enable production mode
4. Check browser console for warnings

## Development

### Hot Reload

Development server supports hot reload:

```bash
npm run dev
```

Changes are reflected immediately in the browser.

### Adding New Pages

1. Create file in `src/app/dashboard/`
2. Add route to navigation
3. Implement page component

Example:

```typescript
// src/app/dashboard/reports/page.tsx
export default function ReportsPage() {
  return (
    <DashboardLayout>
      <h1>Reports</h1>
      {/* Page content */}
    </DashboardLayout>
  )
}
```

### Adding New Components

1. Create file in `src/components/`
2. Export component
3. Use in pages

## Security

- Authentication required for all pages
- JWT token stored in localStorage (persistent)
- Automatic token refresh
- HTTPS recommended for production
- CSP headers configured

## Best Practices

1. **Always use TypeScript** for type safety
2. **Use React Query** for data fetching
3. **Follow component structure** for consistency
4. **Use Tailwind utilities** instead of custom CSS
5. **Implement error boundaries** for graceful errors
6. **Add loading states** for better UX
7. **Make components responsive** with Tailwind breakpoints
8. **Test on different devices** and browsers

## Deployment

### Production Checklist

- [ ] Update API_URL to production server
- [ ] Build production bundle
- [ ] Test all pages and features
- [ ] Verify HTTPS is enabled
- [ ] Check performance metrics
- [ ] Configure error monitoring
- [ ] Set up analytics (optional)

### Nginx Reverse Proxy

For production with HTTPS:

```nginx
server {
    listen 80;
    server_name dlp.company.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dlp.company.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Support

For issues or questions:
- GitHub Issues: [Link]
- Email: support@seceoknight.local
- Documentation: [MASTER_DOCUMENTATION.md](../../MASTER_DOCUMENTATION.md)
