# Jonathan Brownstein - Personal Portfolio Website

A modern, professional portfolio website showcasing skills, experience, and achievements.

## Features

- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile devices
- **Modern UI**: Clean, professional design with smooth animations
- **Smooth Navigation**: Fixed navbar with smooth scrolling to sections
- **Interactive Elements**: Hover effects and fade-in animations
- **Professional Sections**:
  - Hero section with introduction
  - About section
  - Detailed experience timeline
  - Skills showcase
  - Education credentials
  - Contact information

## Getting Started

### Development

1. Open `index.html` in a web browser
2. No build process or dependencies required - it's a static website

### Production Build

For production deployment, minify the files to optimize performance:

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build for production:
   ```bash
   npm run build
   ```

3. Deploy the `dist/` folder to your hosting service

The build process will:
- Minify HTML (remove whitespace, comments, optimize attributes)
- Minify CSS (remove comments, optimize selectors)
- Minify JavaScript (compress and mangle code)
- Copy all static assets (images, PDFs, etc.)
- Generate file size comparison report

## Customization

### Adding Your Photo

Replace the image placeholder in the hero section:

1. Add your photo to the project folder (e.g., `photo.jpg`)
2. In `index.html`, replace the `.image-placeholder` div with:
   ```html
   <img src="photo.jpg" alt="Jonathan Brownstein" style="width: 300px; height: 400px; object-fit: cover; border-radius: 1rem;">
   ```

### Updating Colors

Edit the CSS variables in `styles.css`:
- `--primary-color`: Main brand color
- `--primary-dark`: Darker shade for gradients
- `--accent-color`: Accent color for highlights

### Deploying

**For Production:**
1. Run `npm run build` to create optimized files in the `dist/` folder
2. Deploy the `dist/` folder to your hosting service

**For Development/Testing:**
You can deploy the root folder directly to:
- **GitHub Pages**: Push to a GitHub repository and enable Pages
- **Netlify**: Drag and drop the folder (or connect repo and set build command: `npm run build` and publish directory: `dist`)
- **Vercel**: Connect your repository (auto-detects build settings)
- Any static hosting service

## Google Search (Get Indexed)

The site is set up for search engines (meta tags, canonical URL, sitemap, JSON-LD). To get it **indexed on Google**:

1. **Deploy the site** so it’s live at `https://www.jonathansbrownstein.com` (or your domain).

2. **Add the property in Google Search Console**
   - Go to [Google Search Console](https://search.google.com/search-console)
   - Sign in with your Google account
   - Click **Add property**
   - Choose **URL prefix** and enter: `https://www.jonathansbrownstein.com`
   - Verify ownership using one of the options (HTML file upload, DNS record, or HTML meta tag—your host may offer a “verification” step that gives you a meta tag to add to `index.html`)

3. **Submit the sitemap**
   - In Search Console, open your property → **Sitemaps** (left sidebar)
   - Enter: `sitemap.xml` and click **Submit**
   - Sitemap URL: `https://www.jonathansbrownstein.com/sitemap.xml`

4. **Request indexing** (optional, speeds things up)
   - In Search Console, use **URL Inspection** (top search bar)
   - Enter `https://www.jonathansbrownstein.com/`
   - Click **Request indexing**

Google usually picks up the site within a few days; full indexing can take a bit longer.

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## License

Personal use only.

