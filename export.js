async function main() {
  try {
    const htmlContent = generateHTMLContent()
    console.log('Generated HTML content:', htmlContent) // Add this line for debugging
    writeFileSync(join(outDir, 'index.html'), htmlContent, 'utf8')
    console.log('Export complete.')
  } catch (error) {
    console.error('Export failed:', error)
    process.exit(1)
  }
}
