// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

try {
    const pages = await report.getPages();

    // Retrieve the page that contain the visual. For the sample report it will be the active page
    let page = pages.filter(function (page) {
        return page.isActive
    })[0];

    const visuals = await page.getVisuals();

    // Retrieve the target visual.
    let visual = visuals.filter(function (visual) {
        return visual.name === "VisualContainer4";
    })[0];

    const result = await visual.exportData(models.ExportDataType.Summarized);
    console.log(result.data);
}
catch (errors) {
    console.log(errors);
}