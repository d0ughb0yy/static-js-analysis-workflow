const fs = require('fs');
const path = require('path');
const { SourceMapConsumer } = require('source-map');

async function decodeSourceMaps(inputDir, outputDir) {
  const mapFiles = [];

  function findMaps(dir) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        findMaps(fullPath);
      } else if (entry.name.endsWith('.js.map')) {
        mapFiles.push(fullPath);
      }
    }
  }

  findMaps(inputDir);

  if (mapFiles.length === 0) {
    console.log('No .js.map files found');
    return;
  }

  for (const mapPath of mapFiles) {
    try {
      const mapContent = JSON.parse(fs.readFileSync(mapPath, 'utf8'));
      const relPath = path.relative(inputDir, mapPath);
      const bundleName = path.basename(mapPath, '.js.map');
      const bundleOutputDir = path.join(outputDir, 'decoded-sources', bundleName);
      fs.mkdirSync(bundleOutputDir, { recursive: true });

      await SourceMapConsumer.with(mapContent, null, async (consumer) => {
        const sources = consumer.sources;
        const mappingIndex = {};
        let recoveredCount = 0;

        for (const source of sources) {
          try {
            const sourceContent = consumer.sourceContentFor(source);
            if (sourceContent) {
              const safeName = source.replace(/[^a-zA-Z0-9._-]/g, '_');
              const outPath = path.join(bundleOutputDir, safeName);
              fs.writeFileSync(outPath, sourceContent);
              recoveredCount++;

              // Build line mapping: generatedLine -> original info
              mappingIndex[source] = {};
              consumer.eachMapping((mapping) => {
                if (mapping.source === source) {
                  if (!mappingIndex[source][mapping.generatedLine]) {
                    mappingIndex[source][mapping.generatedLine] = [];
                  }
                  mappingIndex[source][mapping.generatedLine].push({
                    originalLine: mapping.originalLine,
                    originalColumn: mapping.originalColumn,
                    name: mapping.name
                  });
                }
              });
            }
          } catch (e) {
            console.error(`  Failed to recover ${source}: ${e.message}`);
          }
        }

        fs.writeFileSync(
          path.join(bundleOutputDir, 'mapping-index.json'),
          JSON.stringify(mappingIndex, null, 2)
        );

        console.log(`Decoded ${relPath}: ${recoveredCount}/${sources.length} sources -> ${bundleOutputDir}`);
      });
    } catch (e) {
      console.error(`Failed to decode ${mapPath}: ${e.message}`);
    }
  }

  console.log(`\nTotal: ${mapFiles.length} source maps decoded`);
}

const inputDir = process.argv[2] || '.';
const outputDir = process.argv[3] || inputDir;
decodeSourceMaps(inputDir, outputDir).catch(console.error);
