import os
import glob
import re
import shutil

def natural_sort_key(s):
    """Sort strings with numbers in a natural way (e.g., batch_1 before batch_10)"""
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

def create_master_html():
    # Get the current script's directory
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define directories using absolute paths
    html_dir = os.path.join(current_dir, "html_files")
    temp_dir = os.path.join(current_dir, "temp_maps")
    master_file_path = os.path.join(current_dir, "master.html")

    # Create html_files directory if it doesn't exist
    if not os.path.exists(html_dir):
        print(f"Directory '{html_dir}' not found. Creating directory...")
        os.makedirs(html_dir)
        return

    # Find all spider map HTML files
    spider_files = glob.glob(os.path.join(html_dir, "3d_spider_map_batch_*.html"))
    
    if not spider_files:
        print(f"No spider map batch files found in '{html_dir}' directory.")
        return

    # Sort files naturally (batch_1, batch_2, etc.)
    spider_files.sort(key=natural_sort_key)
    
    batch_numbers = []
    for file in spider_files:
        match = re.search(r'batch_(\d+)', file)
        if match:
            batch_numbers.append(match.group(1))
    
    # Create master HTML file with navigation
    with open(master_file_path, "w", encoding='utf-8') as master_file:
        # ... existing HTML template code ...
        # Update the iframe src path to use relative path
        iframe_src = os.path.join("html_files", "3d_spider_map_batch_1.html").replace("\\", "/")
        
        # Write the HTML content with updated paths
        master_file.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ethereum Transaction Spider Maps</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background-color: #2a2a72;
            color: white;
            padding: 15px;
            text-align: center;
        }
        .controls {
            display: flex;
            justify-content: center;
            padding: 10px;
            background-color: #f0f0f0;
        }
        .btn {
            padding: 8px 16px;
            margin: 0 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        .btn:hover {
            background-color: #45a049;
        }
        .btn:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .batch-indicator {
            margin: 0 20px;
            font-size: 16px;
            line-height: 2;
        }
        .iframe-container {
            flex: 1;
            width: 100%;
        }
        iframe {
            width: 100%;
            height: 100%;
            border: none;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ethereum Transaction Spider Maps</h1>
    </div>
    
    <div class="controls">
        <button id="prevBtn" class="btn">Previous Batch</button>
        <div class="batch-indicator">
            Batch <span id="currentBatch">1</span> of <span id="totalBatches">""" + str(len(spider_files)) + """</span>
        </div>
        <button id="nextBtn" class="btn">Next Batch</button>
    </div>
    
    <div class="iframe-container">
        <iframe id="mapFrame" src=\"""" + iframe_src + """\"></iframe>
    </div>

    <script>
        const batchFiles = [
""")
        
        # Add the file paths as a JavaScript array with relative paths
        for file_path in spider_files:
            relative_path = os.path.join("html_files", os.path.basename(file_path)).replace("\\", "/")
            master_file.write(f'            "{relative_path}",\n')
        
        master_file.write("""        ];
        
        const currentBatchElem = document.getElementById('currentBatch');
        const totalBatchesElem = document.getElementById('totalBatches');
        const mapFrame = document.getElementById('mapFrame');
        const prevBtn = document.getElementById('prevBtn');
        const nextBtn = document.getElementById('nextBtn');
        
        let currentBatchIndex = 0;
        totalBatchesElem.textContent = batchFiles.length;
        
        function updateIframe() {
            mapFrame.src = batchFiles[currentBatchIndex];
            currentBatchElem.textContent = currentBatchIndex + 1;
            
            // Update button states
            prevBtn.disabled = currentBatchIndex === 0;
            nextBtn.disabled = currentBatchIndex === batchFiles.length - 1;
        }
        
        prevBtn.addEventListener('click', () => {
            if (currentBatchIndex > 0) {
                currentBatchIndex--;
                updateIframe();
            }
        });
        
        nextBtn.addEventListener('click', () => {
            if (currentBatchIndex < batchFiles.length - 1) {
                currentBatchIndex++;
                updateIframe();
            }
        });
        
        // Initial setup
        updateIframe();
    </script>
</body>
</html>""")

    print(f"Master HTML file created successfully: '{master_file_path}'")
    print(f"Found and combined {len(spider_files)} batch files: {', '.join(['batch_' + num for num in batch_numbers])}")

    # Don't move files to temp_dir, keep them in html_files
    print(f"Spider map files are available in '{html_dir}' directory")
    print(f"Access the visualization through '{master_file_path}'")

if __name__ == "__main__":
    create_master_html()