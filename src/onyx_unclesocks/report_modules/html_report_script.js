document.addEventListener('DOMContentLoaded', function() {
    const expandableRows = document.querySelectorAll('.expandable-row');

    expandableRows.forEach(row => {
        const expandedContent = row.nextElementSibling;

        row.addEventListener('click', function() {
            expandedContent.classList.toggle('expanded');
        });
    });
});