// Set dimensions and margins for the chart
const margin = { top: 70, right: 30, bottom: 40, left: 80 };
const width = 1700 - margin.left - margin.right;
const height = 500 - margin.top - margin.bottom;

// Set up the x and y scales
const x = d3.scaleTime().range([0, width]);
const y = d3.scaleLinear().range([height, 0]);

let tickMonth = d3.timeMonth.every(6);

// Set up the line generators
const line1 = d3.line()
  .x(d => x(d.date))
  .y(d => y(d.ipv4));

const line2 = d3.line()
  .x(d => x(d.date))
  .y(d => y(d.ipv6));


// Create tooltip div
const tooltip = d3.select("body")
  .append("div")
  .attr("class", "tooltip");

// Load and process the data
d3.csv("ROVoverTime.csv").then(data => {
  // Parse the date and convert the ROV values to numbers
  const parseDate = d3.timeParse("%Y-%m-%d %H:%M:%S");
  data.forEach(d => {
    d.date = parseDate(d.date);
    d.ipv4 = +d.ipv4;
    d.ipv6 = +d.ipv6;
    d.date_file = d.date_file;
  });

  function updateChart(data) {

    // Remove any existing SVG to create a fresh chart
    d3.select("#line-chart").select("svg").remove();

    // Create the SVG element and append it to the chart container
    const svg = d3.select("#line-chart")
    .append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", `translate(${margin.left},${margin.top})`);

    // Set the domains for the x and y scales
    x.domain(d3.extent(data, d => d.date));
    y.domain([0, 100]);

    // Add the x-axis
    svg.append("g")
      .attr("transform", `translate(0,${height})`)
      .style("font-size", "14px")
      .call(d3.axisBottom(x)
        .tickValues(x.ticks(tickMonth)) // Display ticks every 6 months
        .tickFormat(d3.timeFormat("%b %Y"))) // Format the tick labels to show Month and Year
      //.call(g => g.select(".domain").remove()) // Remove the x-axis line
      .selectAll(".tick line") // Select all tick lines
      .style("stroke-opacity", 0);

    svg.selectAll(".tick text")
      .attr("fill", "#777");

    // Add vertical gridlines
    svg.selectAll("xGrid")
      .data(x.ticks(20))
      .join("line")
      .attr("x1", d => x(d))
      .attr("x2", d => x(d))
      .attr("y1", 0)
      .attr("y2", height)
      .attr("stroke", "#e0e0e0")
      .attr("stroke-width", .5);

    // Add the y-axis
    svg.append("g")
      .style("font-size", "14px")
      .call(d3.axisLeft(y)
        .ticks(5)
        .tickFormat(d => {
          if (isNaN(d)) return "";
          return d + "%";
        })
        .tickSize(0)
        .tickPadding(10))
      //.call(g => g.select(".domain").remove()) // Remove the y-axis line
      .selectAll(".tick text")
      .style("fill", "#777") // Make the font color grayer
      .style("visibility", (d, i, nodes) => {
        if (i === 0) {
          return "hidden"; // Hide the first and last tick labels
        } else {
          return "visible"; // Show the remaining tick labels
        }
      });

    // Add Y-axis label
    svg.append("text")
      .attr("transform", "rotate(-90)")
      .attr("y", 0 - margin.left)
      .attr("x", 0 - (height / 2))
      .attr("dy", "1em")
      .style("text-anchor", "middle")
      .style("font-size", "14px")
      .style("fill", "#777")
      .style("font-family", "sans-serif")
      .text("% of full feeder ASes");

    // Add horizontal gridlines
    svg.selectAll("yGrid")
      .data(y.ticks(5).slice(1)) //TODO: Fix this line
      .join("line")
      .attr("x1", 0)
      .attr("x2", width)
      .attr("y1", d => y(d))
      .attr("y2", d => y(d))
      .attr("stroke", "#e0e0e0")
      .attr("stroke-width", .5);
    
    // Add the line paths
    const path1 = svg.append("path")
      .datum(data)
      .attr("fill", "none")
      .attr("stroke", "steelblue")
      .attr("stroke-width", 1)
      .attr("d", line1);

    const path2 = svg.append("path")
      .datum(data)
      .attr("fill", "none")
      .attr("stroke", "orange")
      .attr("stroke-width", 1)
      .attr("d", line2);

    // Add circle elements for both lines
    const circle1 = svg.append("circle")
      .attr("r", 0)
      .attr("fill", "steelblue")
      .style("stroke", "white")
      .attr("opacity", .70)
      .style("pointer-events", "none");

    const circle2 = svg.append("circle")
      .attr("r", 0)
      .attr("fill", "orange")
      .style("stroke", "white")
      .attr("opacity", .70)
      .style("pointer-events", "none");

    // Create a listening rectangle
    const listeningRect = svg.append("rect")
      .attr("width", width)
      .attr("height", height)
      .style("fill", "none")
      .style("pointer-events", "all");

    // Create the mouse move function
    listeningRect.on("mousemove", function (event) {
      const [xCoord] = d3.pointer(event, this);
      const bisectDate = d3.bisector(d => d.date).left;
      const x0 = x.invert(xCoord);
      const i = bisectDate(data, x0, 1);
      const d0 = data[i - 1];
      const d1 = data[i];
      const d = x0 - d0.date > d1.date - x0 ? d1 : d0;
      const xPos = x(d.date);
      const yPos1 = y(d.ipv4);
      const yPos2 = y(d.ipv6);

      //Input date_file to scatterDateInput
      document.getElementById("scatterDateInput").value = d.date_file;

      // Update the circle positions
      circle1.attr("cx", xPos).attr("cy", yPos1);
      circle2.attr("cx", xPos).attr("cy", yPos2);

      // Add transition for the circle radii
      circle1.transition().duration(50).attr("r", 5);
      circle2.transition().duration(50).attr("r", 5);

      // Add the tooltip
      tooltip
        .style("display", "block")
        .style("left", `${xPos + 100}px`)
        .style("top", `${yPos1 + 50}px`)
        .html(`<strong>Date:</strong> ${d.date.toLocaleDateString()}<br>
              <strong>IPv4:</strong> ${d.ipv4 !== undefined ? (d.ipv4).toFixed(1) + "%" : 'N/A'}<br>
              <strong>IPv6:</strong> ${d.ipv6 !== undefined ? (d.ipv6).toFixed(1) + "%" : 'N/A'}`);
    });

    //Click scatterUpdateButton on mouse click
    listeningRect.on("click", function (event) {
      document.getElementById("scatterUpdateButton").click();
    });

    // Listening rectangle mouse leave function
    listeningRect.on("mouseleave", function () {
      circle1.transition().duration(50).attr("r", 0);
      circle2.transition().duration(50).attr("r", 0);
      tooltip.style("display", "none");
    });

    // Add the chart title
    svg.append("text")
      .attr("class", "chart-title")
      .attr("x", (width / 2))
      .attr("y", -margin.top / 2)
      .style("font-size", "24px")
      .style("font-family", "sans-serif")
      .style("text-anchor", "middle")
      .text("ROV Over Time");

    // Add the legend
    const legend = svg.append("g")
      .attr("transform", `translate(${width - 100}, 10)`);
    legend.append("circle")
      .attr("cx", 0)
      .attr("cy", 0)
      .attr("r", 5)
      .attr("fill", "steelblue");
    legend.append("text")
      .attr("x", 10)
      .attr("y", 5)
      .text("IPv4")
      .style("font-size", "14px")
      .style("font-family", "sans-serif");
    legend.append("circle")
      .attr("cx", 0)
      .attr("cy", 20)
      .attr("r", 5)
      .attr("fill", "orange");
    legend.append("text")
      .attr("x", 10)
      .attr("y", 25)
      .text("IPv6")
      .style("font-size", "14px")
      .style("font-family", "sans-serif");
    
    // Create SVG buttons
    const buttons = svg.append("g")
      .attr("class", "buttons")
      .attr("transform", `translate(${width - margin.right - 350},${margin.top - 100})`);

    const buttonData = [
      { label: "Last 6 Months", timeframe: "6m" },
      { label: "Last Year", timeframe: "1y" },
      { label: "Last 2 Years", timeframe: "2y" },
      { label: "All Time", timeframe: "all" }
    ];

    // Add buttons as rectangles and text
    buttons.selectAll("rect")
      .data(buttonData)
      .enter()
      .append("rect")
      .attr("x", (d, i) => i * 100)
      .attr("y", -20)
      .attr("width", 90)
      .attr("height", 30)
      .attr("fill", "lightgray")
      .attr("stroke", "black")
      .attr("stroke-width", 1)
      .style("cursor", "pointer")
      .on("click", (event, d) => filterData(d.timeframe));

    buttons.selectAll("text")
      .data(buttonData)
      .enter()
      .append("text")
      .attr("x", (d, i) => i * 100 + 45)
      .attr("y", 0)
      .attr("text-anchor", "middle")
      .attr("fill", "black")
      .style("font-size", "12px")
      .style("cursor", "pointer")
      .text(d => d.label)
      .on("click", (event, d) => filterData(d.timeframe));

  }

  // Filter data based on timeframe
  function filterData(timeframe) {
    const now = new Date();
    let filteredData;

    switch (timeframe) {
      case "6m":
        filteredData = data.filter(d => d.date >= d3.timeMonth.offset(now, -6));
        tickMonth = d3.timeMonth.every(1);
        break;
      case "1y":
        filteredData = data.filter(d => d.date >= d3.timeYear.offset(now, -1));
        tickMonth = d3.timeMonth.every(1);
        break;
      case "2y":
        filteredData = data.filter(d => d.date >= d3.timeYear.offset(now, -2));
        tickMonth = d3.timeMonth.every(2);
        break;
      case "all":
        filteredData = data;
        tickMonth = d3.timeMonth.every(6);
        break;
      default:
        filteredData = data;
        tickMonth = d3.timeMonth.every(6);
    }

    updateChart(filteredData);
  }

  // Initialize the chart
  updateChart(data);

  

    

});