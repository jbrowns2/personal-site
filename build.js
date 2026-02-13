const fs = require('fs');
const path = require('path');
const { minify: minifyHTML } = require('html-minifier-terser');
const cssnano = require('cssnano');
const postcss = require('postcss');
const { minify: minifyJS } = require('terser');

const distDir = path.join(__dirname, 'dist');

// Create dist directory if it doesn't exist
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Copy directories
const copyDir = (src, dest) => {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
};

async function build() {
  console.log('🚀 Starting production build...\n');

  try {
    // Minify HTML
    console.log('📄 Minifying HTML...');
    const html = fs.readFileSync('index.html', 'utf8');
    const minifiedHTML = await minifyHTML(html, {
      collapseWhitespace: true,
      removeComments: true,
      removeRedundantAttributes: true,
      removeScriptTypeAttributes: true,
      removeStyleLinkTypeAttributes: true,
      useShortDoctype: true,
      minifyCSS: false, // We'll minify CSS separately
      minifyJS: false, // We'll minify JS separately
      removeEmptyAttributes: true,
      removeOptionalTags: true,
      removeTagWhitespace: true,
      sortAttributes: true,
      sortClassName: true
    });
    fs.writeFileSync(path.join(distDir, 'index.html'), minifiedHTML);
    console.log('✅ HTML minified\n');

    // Minify CSS
    console.log('🎨 Minifying CSS...');
    const css = fs.readFileSync('styles.css', 'utf8');
    const result = await postcss([cssnano({
      preset: ['default', {
        discardComments: { removeAll: true },
        normalizeWhitespace: true
      }]
    })]).process(css, { from: 'styles.css', to: 'styles.css' });
    fs.writeFileSync(path.join(distDir, 'styles.css'), result.css);
    console.log('✅ CSS minified\n');

    // Minify JavaScript
    console.log('⚡ Minifying JavaScript...');
    const js = fs.readFileSync('script.js', 'utf8');
    const minifiedJS = await minifyJS(js, {
      compress: {
        drop_console: false, // Keep console logs for debugging
        drop_debugger: true,
        pure_funcs: []
      },
      mangle: true,
      format: {
        comments: false
      }
    });
    fs.writeFileSync(path.join(distDir, 'script.js'), minifiedJS.code);
    console.log('✅ JavaScript minified\n');

    // Copy static files
    console.log('📁 Copying static files...');
    if (fs.existsSync('images')) {
      copyDir('images', path.join(distDir, 'images'));
      console.log('✅ Images copied');
    }
    if (fs.existsSync('Projects')) {
      copyDir('Projects', path.join(distDir, 'Projects'));
      console.log('✅ Projects copied');
    }
    
    // Copy other static files
    const staticFiles = ['robots.txt', 'sitemap.xml', 'favicon.svg', 'favicon.ico'];
    staticFiles.forEach(file => {
      if (fs.existsSync(file)) {
        fs.copyFileSync(file, path.join(distDir, file));
        console.log(`✅ ${file} copied`);
      }
    });

    console.log('\n✨ Build complete! Production files are in the /dist directory');
    console.log('\n📊 File size comparison:');
    
    const originalHTML = fs.statSync('index.html').size;
    const minifiedHTMLSize = fs.statSync(path.join(distDir, 'index.html')).size;
    const originalCSS = fs.statSync('styles.css').size;
    const minifiedCSSSize = fs.statSync(path.join(distDir, 'styles.css')).size;
    const originalJS = fs.statSync('script.js').size;
    const minifiedJSSize = fs.statSync(path.join(distDir, 'script.js')).size;
    
    console.log(`HTML: ${(originalHTML / 1024).toFixed(2)} KB → ${(minifiedHTMLSize / 1024).toFixed(2)} KB (${((1 - minifiedHTMLSize / originalHTML) * 100).toFixed(1)}% reduction)`);
    console.log(`CSS: ${(originalCSS / 1024).toFixed(2)} KB → ${(minifiedCSSSize / 1024).toFixed(2)} KB (${((1 - minifiedCSSSize / originalCSS) * 100).toFixed(1)}% reduction)`);
    console.log(`JS: ${(originalJS / 1024).toFixed(2)} KB → ${(minifiedJSSize / 1024).toFixed(2)} KB (${((1 - minifiedJSSize / originalJS) * 100).toFixed(1)}% reduction)`);
    
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

build();
