(function () {    
    // Set dimensions and margins for the chart
    const margin = { top: 70, right: 30, bottom: 40, left: 80 };
    const width = 900 - margin.left - margin.right;
    const height = 500 - margin.top - margin.bottom;

    const max_invalids = 5500;

    // Create the SVG element and append it to the chart container
    const svg = d3.select("#scatter-chartipv4")
    .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
    .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    let date_file = "20230601"

    function updateChart(date_file, ipv) {
        
        let filename = "RPKIinvalidFiles/RPKIinvalid_" + date_file + "_" + ipv + ".csv"
        d3.text(filename).then(function(csvText) {
            // Split the CSV text into an array of lines
            const lines = csvText.split('\n');
        
            // Process the first two lines separately
            const filtering_threshold = lines[0].split(',')[1].trim();
            const feeder_threshold = lines[1].split(',')[1].trim();
        
            // console.log('filtering_threshold IP' + ip + ':', filtering_threshold);
            // console.log('feeder_threshold IP' + ip + ':', feeder_threshold);
        
            // Extract the relevant lines for d3.csvParse (start from the third line)
            const csvData = lines.slice(2).join('\n');
        
            // Parse the data using d3.csvParse
            const data = d3.csvParse(csvData, function(d) {
                return {
                    rpki_invalids: +d.rpki_invalids,
                    pos: +d.pos,
                    asn: +d.asn
                };
            });

            // Remove any existing SVG to create a fresh chart
            d3.select("#scatter-chartip" + ipv).select("svg").remove();
            
            // Create the SVG element and append it to the chart container
            const svg = d3.select("#scatter-chartip" + ipv)
            .append("svg")
              .attr("width", width + margin.left + margin.right)
              .attr("height", height + margin.top + margin.bottom)
            .append("g")
              .attr("transform", `translate(${margin.left},${margin.top})`);

            // Add X axis
            var x = d3.scaleLinear()
              .domain([0, max_invalids])
              .range([ 0, width ]);
            svg.append("g")
              .attr("transform", "translate(0," + height + ")")
              .call(d3.axisBottom(x));

            // Add Y axis
            var y = d3.scaleLinear()
              .domain([0, d3.max(data, d => d.pos)])
              .range([ height, 0]);
            svg.append("g")
              .call(d3.axisLeft(y));

            // Add dots
            svg.append('g')
              .selectAll("dot")
              .data(data)
              .enter()
              .append("circle")
                .attr("cx", function (d) { return x(d.rpki_invalids); } )
                .attr("cy", function (d) { return y(d.pos); } )
                .attr("r", 1.5)
                .style("fill", function(d) {
                    // Conditional coloring logic
                    if (d.rpki_invalids < filtering_threshold && d.pos > feeder_threshold) {
                        return "purple"; // Color for points in the specified region
                    } else {
                        return "#69b3a2"; // Default color
                    }
                });

            // Add feeder threshold line
            svg.append("line")
              .attr("x1", x(0))
              .attr("x2", x(max_invalids))
              .attr("y1", y(feeder_threshold))
              .attr("y2", y(feeder_threshold))
              .attr("stroke", "red")  // Color of the threshold line
              .attr("stroke-width", 1) // Thickness of the line
              .style("stroke-dasharray", ("4,2")); // Optional: dashed line

            // Add filtering threshold line
            svg.append("line")
              .attr("x1", x(filtering_threshold))
              .attr("x2", x(filtering_threshold))
              .attr("y1", y(d3.max(data, d => d.pos)))
              .attr("y2", y(0))
              .attr("stroke", "green")  // Color of the threshold line
              .attr("stroke-width", 1) // Thickness of the line
              .style("stroke-dasharray", ("4,2")); // Optional: dashed line

            // Add the X-axis label
            svg.append("text")
              .attr("transform", `translate(${width / 2}, ${height + 35})`)
              .style("text-anchor", "middle")
              .style("font-size", "14px")
              .style("fill", "#777")
              .style("font-family", "sans-serif")
              .text("RPKI-Invalid ip" + ipv + " routes");

            // Add the Y-axis label
            svg.append("text")
              .attr("transform", "rotate(-90)")
              .attr("y", 0 - margin.left)
              .attr("x", 0 - (height / 2))
              .attr("dy", "1em")
              .style("text-anchor", "middle")
              .style("font-size", "14px")
              .style("fill", "#777")
              .style("font-family", "sans-serif")
              .text("Unique Routes");

            // Add the legend
            const legend = svg.append("g")
                .attr("transform", `translate(${width - 170}, ${height - 100})`)
                .style("font-size", "12px")
                .style("font-family", "sans-serif");

            legend.append("circle")
                .attr("cx", 10)
                .attr("cy", 0)
                .attr("r", 5)
                .style("fill", "purple");

            legend.append("text")
                .attr("x", 30)
                .attr("y", 5)
                .text("RPKI-Filtering AS");

            legend.append("circle")
                .attr("cx", 10)
                .attr("cy", 15)
                .attr("r", 5)
                .style("fill", "#69b3a2");

            legend.append("text")
                .attr("x", 30)
                .attr("y", 20)
                .text("Non RPKI-Filtering AS");

            //Add the threshold lines to the legend
            legend.append("line")
                .attr("x1", 0)
                .attr("x2", 20)
                .attr("y1", 30)
                .attr("y2", 30)
                .attr("stroke", "red")
                .attr("stroke-width", 1)
                .style("stroke-dasharray", ("4,2"));

            legend.append("text")
                .attr("x", 30)
                .attr("y", 35)
                .text("Full Feeder threshold");

            legend.append("line")
                .attr("x1", 0)
                .attr("x2", 20)
                .attr("y1", 45)
                .attr("y2", 45)
                .attr("stroke", "green")
                .attr("stroke-width", 1)
                .style("stroke-dasharray", ("4,2"));

            legend.append("text")
                .attr("x", 30)
                .attr("y", 50)
                .text("RPKI Filtering threshold");

            // Add the title
            const formattedDate = `${date_file.substring(6, 8)}/${date_file.substring(4, 6)}/${date_file.substring(0, 4)}`;
            svg.append("text")
                .attr("x", (width / 2))
                .attr("y", 0 - (margin.top / 2))
                .attr("text-anchor", "middle")
                .style("font-size", "16px")
                .text("Scatter plot of RPKI IP" + ipv + " routes for " + formattedDate);
        });
    }

    updateChart(date_file, "v4");
    updateChart(date_file, "v6");

    // Simulate clicking the button to update the chart
    document.getElementById("scatterUpdateButton").addEventListener("click", () => {
        // Get the value from the input fields
        const inputValue = document.getElementById("scatterDateInput").value;

        // Update the chart with the manipulated data
        updateChart(inputValue, "v4");
        updateChart(inputValue, "v6");
    });


})();