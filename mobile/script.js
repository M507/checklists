document.addEventListener('DOMContentLoaded', function() {
    
    if (typeof checklistItems === 'undefined') {
        console.error("Error: checklistItems is not loaded!");
        return;
    }

    // Setup button event listeners
    const saveButton = document.getElementById('saveButton');
    const importButton = document.getElementById('importButton');
    const fileInput = document.getElementById('fileInput');

    saveButton.addEventListener('click', saveProgress);
    importButton.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', importProgress);

    // Load the checklist automatically when the page loads
    loadChecklist(checklistItems);

    function loadChecklist(items) {
        const tbody = document.querySelector('#checklistTable tbody');
        tbody.innerHTML = ''; // Clear existing entries
        items.forEach((item, index) => {
            const row = tbody.insertRow();
            
            // Add a column for the checklist number
            row.insertCell(0).textContent = index + 1;
    
            row.insertCell(1).textContent = item.name;
            row.insertCell(2).textContent = item.description;
    
            const commentCell = row.insertCell(3);
            const input = document.createElement('input');
            input.type = 'text';
            input.value = item.comments;
            input.onchange = () => item.comments = input.value;
            commentCell.appendChild(input);
    
            const checkCell = row.insertCell(4);
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = item.done;
            checkbox.onchange = () => item.done = checkbox.checked;
            checkCell.appendChild(checkbox);
    
            row.insertCell(5).textContent = item.tags;
        });
    
        enableColumnResizing(); // Ensure resizing works after table update
    }
    

    function saveProgress() {
        const data = JSON.stringify(checklistItems);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'checklistProgress.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function importProgress(event) {
        const file = event.target.files[0];
        const reader = new FileReader();
        reader.onload = function(e) {
            const items = JSON.parse(e.target.result);
            loadChecklist(items);
        };
        reader.readAsText(file);
    }



    
});



function filterTags() {
    const selectedTag = document.getElementById('tagFilter').value;
    const table = document.getElementById('checklistTable');
    const headers = table.querySelectorAll('thead th');
    let tagsColumnIndex = -1;

    // Find the column index for "Tags"
    headers.forEach((header, index) => {
        if (header.textContent.trim().toLowerCase() === 'tags') {
            tagsColumnIndex = index;
        }
    });

    if (tagsColumnIndex === -1) return; // Exit if "Tags" column is not found

    const rows = table.querySelector('tbody').rows;
    for (let i = 0; i < rows.length; i++) {
        const tagsCell = rows[i].cells[tagsColumnIndex].textContent;
        if (selectedTag === 'all' || tagsCell.includes(selectedTag)) {
            rows[i].style.display = ''; // Show row
        } else {
            rows[i].style.display = 'none'; // Hide row
        }
    }
}

// Call filterTags initially if needed
filterTags();


