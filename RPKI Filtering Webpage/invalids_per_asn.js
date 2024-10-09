(function () {    
    // Set dimensions and margins for the chart
    const margin = { top: 70, right: 30, bottom: 40, left: 80 };
    const width = 1500 - margin.left - margin.right;
    const height = 500 - margin.top - margin.bottom;

    // Parse the date/time
    const parseDate = d3.timeParse("%Y-%m-%d %H:%M:%S");

    // Set up the x and y scales
    const x = d3.scaleTime().range([0, width]);
    const y = d3.scaleLinear().range([height, 0]);

    // Create the SVG element and append it to the chart container
    const svg = d3.select("#invalids-asn-chart")
    .append("svg")
      .attr("width", width + margin.left + margin.right)
      .attr("height", height + margin.top + margin.bottom)
    .append("g")
      .attr("transform", `translate(${margin.left},${margin.top})`);

    d3.csv("Tier1ASes_IPv4_RPKIinvalidsCount_transposed.csv", d => {
      d.date = parseDate(d.date);
      for (let key in d) {
        if (key !== "date" && d[key] !== "NA") {
          d[key] = +d[key];  // Convert string to number
        } else if (d[key] === "NA") {
          d[key] = null; // Handle NA values
        }
      }
      console.log(d)
      return d;
    }).then(data => {

      // Get the columns (headers) excluding the date
      const keys = data.columns.slice(1);
      // // Parse the dates and convert the numerical values from strings to numbers
      // data.forEach(d => {
      //   d.date = new Date(d.date);
      //   for (let key in d) {
      //       if (key !== "date" && d[key] !== 'NA') d[key] = +d[key];
      //   }
      // });

      // Create a color scale
      const color = d3.scaleOrdinal(d3.schemeCategory10);

      // Set the domains for the x and y scales
      x.domain(d3.extent(data, d => d.date));
      y.domain([
        0,
        d3.max(data, d => d3.max(keys, key => d[key]))
      ]);

      // Add the x-axis
      svg.append("g")
        .attr("transform", `translate(0,${height})`)
        .style("font-size", "14px")
        .call(d3.axisBottom(x)
          .tickValues(x.ticks(d3.timeMonth.every(6))) // Display ticks every 6 months
          .tickFormat(d3.timeFormat("%b %Y"))) // Format the tick labels to show Month and Year
        .selectAll(".tick line") // Select all tick lines
        .style("stroke-opacity", 0);

      svg.selectAll(".tick text")
        .attr("fill", "#777");

      // Add the y-axis
      svg.append("g")
        .style("font-size", "14px")
        .call(d3.axisLeft(y));

      // Define the line generator
      const line = d3.line()
        .x(d => x(d.date))
        .y(d => y(d.value));

      // Draw the lines for each column (ISP)
      keys.forEach((key, i) => {
        svg.append("path")
           .datum(data)
           .attr("fill", "none")
           .attr("stroke", color(key))
           .attr("stroke-width", 1.5)
           .attr("d", line.y(d => y(d[key])));
        
        // Add labels for each line
        svg.append("text")
          .attr("transform", `translate(${width},${y(data[data.length - 1][key])})`)
          .attr("dy", "0.35em")
          .style("font-size", "10px")
          .style("fill", color(key))
          .text(key);
      });

      // Add the title for the chart
      svg.append("text")
        .attr("x", width / 2)
        .attr("y", 0 - (margin.top / 2))
        .attr("text-anchor", "middle")
        .style("font-size", "16px")
        .text("RPKI Invalids per ASN");

      // Add the Y-axis label
      svg.append("text")
        .attr("transform", "rotate(-90)")
        .attr("y", 0 - margin.left)
        .attr("x", 0 - (height / 2))
        .attr("dy", "1em")
        .style("text-anchor", "middle")
        .style("font-size", "14px")
        .text("# Of RPKI Invalid Routes");

    })


})();