# ==============================================================================
# DAST & SCA Security Analytics Simulation Dashboard
# Typography: Cambria
# Data Simulation Engines: GAM (Generalized Additive Model) & GMM (Gaussian Mixture Model)
# ==============================================================================

library(shiny)
library(bslib)
library(ggplot2)
library(plotly)
library(DT)
library(dplyr)
library(mgcv)
library(mclust)

# ------------------------------------------------------------------------------
# 1. Custom UI Definition with Cambria Styling
# ------------------------------------------------------------------------------

cambria_theme <- bs_theme(
  version = 5,
  bootswatch = "flatly",
  primary = "#1A365D",    # Deep Navy
  secondary = "#2B6CB0",  # Steel Blue
  success = "#2F855A",    # Security Green
  danger = "#C53030",     # Alert Red
  base_font = "Cambria"
)

ui <- fluidPage(
  theme = cambria_theme,
  
  # Inject Custom CSS for strict Cambria font enforcement across all components
  tags$head(
    tags$style(HTML("
      body, h1, h2, h3, h4, h5, h6, .card-title, .form-control, .btn, table, th, td {
        font-family: 'Cambria', 'Georgia', serif !important;
      }
      .metric-card {
        background-color: #F7FAFC;
        border-left: 4px solid #1A365D;
        padding: 15px;
        border-radius: 6px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      }
      .metric-value {
        font-size: 24px;
        font-weight: bold;
        color: #1A365D;
      }
      .metric-label {
        font-size: 13px;
        color: #4A5568;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
    "))
  ),
  
  # Header Section
  titlePanel(
    div(
      style = "padding: 10px 0px; border-bottom: 2px solid #1A365D; margin-bottom: 20px;",
      h2("DAST & SCA Security Simulation Engine", style = "color: #1A365D; font-weight: bold; margin: 0;"),
      p("Synthetic Vulnerability Dataset Generation via GAM & GMM Modeling", style = "color: #718096; margin-top: 5px;")
    )
  ),
  
  # Sidebar + Main Layout
  sidebarLayout(
    sidebarPanel(
      width = 3,
      h4("Simulation Parameters", style = "font-weight: bold; color: #1A365D;"),
      hr(),
      
      selectInput(
        "sim_method", 
        "Data Generation Engine:",
        choices = c("Generalized Additive Model (GAM)" = "GAM", 
                    "Gaussian Mixture Model (GMM)" = "GMM")
      ),
      
      numericInput("sample_size", "Sample Size (N Findings):", value = 500, min = 100, max = 5000, step = 100),
      
      sliderInput("dast_ratio", "DAST vs. SCA Ratio (% DAST):", min = 10, max = 90, value = 50, post = "%"),
      
      sliderInput("noise_level", "System Noise / Variance Multiplier:", min = 0.1, max = 2.0, value = 1.0, step = 0.1),
      
      conditionalPanel(
        condition = "input.sim_method == 'GMM'",
        numericInput("num_clusters", "GMM Risk Clusters (Mixture Components):", value = 3, min = 2, max = 5)
      ),
      
      conditionalPanel(
        condition = "input.sim_method == 'GAM'",
        sliderInput("gam_k", "GAM Spline Basis Dimensions (Smoothness):", min = 3, max = 10, value = 5)
      ),
      
      hr(),
      actionButton("btn_generate", "Generate Synthetic Data", class = "btn-primary w-100", icon = icon("sync")),
      br(), br(),
      downloadButton("btn_download", "Download CSV Dataset", class = "btn-success w-100")
    ),
    
    mainPanel(
      width = 9,
      
      # KPI Cards Row (Fixed wrappers)
      fluidRow(
        column(3, div(class = "metric-card", div(class = "metric-label", "Total Findings"), div(class = "metric-value", textOutput("kpi_total")))),
        column(3, div(class = "metric-card", div(class = "metric-label", "Critical / High Risk"), div(class = "metric-value", textOutput("kpi_critical")))),
        column(3, div(class = "metric-card", div(class = "metric-label", "Avg. CVSS Score"), div(class = "metric-value", textOutput("kpi_cvss")))),
        column(3, div(class = "metric-card", div(class = "metric-label", "Mean Remediation Time"), div(class = "metric-value", textOutput("kpi_remediation"))))
      ),
      br(),
      
      # Tabs Section
      tabsetPanel(
        type = "tabs",
        
        # Tab 1: Visualizations
        tabPanel(
          "Visual Analytics",
          br(),
          fluidRow(
            column(6, card(card_header("CVSS Score Distribution by Testing Method"), plotlyOutput("plot_cvss_dist", height = "320px"))),
            column(6, card(card_header("Model Fit: CVSS Score vs. Remediation Days"), plotlyOutput("plot_model_fit", height = "320px")))
          ),
          br(),
          fluidRow(
            column(6, card(card_header("Vulnerability Severity Count by Category"), plotlyOutput("plot_severity_bar", height = "320px"))),
            column(6, card(card_header("SCA Dependency Depth vs. Exploitability Index"), plotlyOutput("plot_sca_depth", height = "320px")))
          )
        ),
        
        # Tab 2: Statistical Summaries
        tabPanel(
          "Statistical Summary",
          br(),
          h4("Summary Statistics by Security Testing Type", style = "font-weight: bold;"),
          tableOutput("table_summary_type"),
          hr(),
          h4("Summary Statistics by Vulnerability Severity Level", style = "font-weight: bold;"),
          tableOutput("table_summary_severity")
        ),
        
        # Tab 3: Dataset Explorer
        tabPanel(
          "Raw Data Explorer",
          br(),
          DTOutput("raw_data_table")
        )
      )
    )
  )
)

# ------------------------------------------------------------------------------
# 2. Server Logic (GAM & GMM Simulation Engines)
# ------------------------------------------------------------------------------

server <- function(input, output, session) {
  
  # Reactive Data Generator
  simulated_data <- eventReactive(input$btn_generate, ignoreNULL = FALSE, {
    n <- input$sample_size
    dast_pct <- input$dast_ratio / 100
    n_dast <- round(n * dast_pct)
    n_sca <- n - n_dast
    noise <- input$noise_level
    
    # --------------------------------------------------------------------------
    # Engine A: GAM (Generalized Additive Model) Based Simulation
    # --------------------------------------------------------------------------
    if (input$sim_method == "GAM") {
      testing_type <- c(rep("DAST", n_dast), rep("SCA", n_sca))
      
      x_base <- runif(n, 0, 10)
      smooth_fn <- function(x) { 5 + 2 * (x^1.5) - 0.3 * sin(x * 2) }
      remediation_days <- pmax(1, round(smooth_fn(x_base) * noise + rnorm(n, mean = 0, sd = 4)))
      
      df_gam_raw <- data.frame(CVSS = x_base, Remediation_Days = remediation_days)
      gam_model <- gam(Remediation_Days ~ s(CVSS, k = input$gam_k), data = df_gam_raw)
      fitted_remediation <- predict(gam_model, newdata = df_gam_raw)
      
      exploitability <- pmin(1.0, pmax(0.0, 0.1 * x_base + rnorm(n, 0.2, 0.15 * noise)))
      dep_depth <- ifelse(testing_type == "SCA", sample(1:6, n, replace = TRUE, prob = c(0.4, 0.3, 0.15, 0.1, 0.03, 0.02)), 0)
      
      df <- data.frame(
        Finding_ID = paste0("VULN-", 1000 + 1:n),
        Type = testing_type,
        CVSS_Score = round(x_base, 1),
        Remediation_Days = pmax(1, round(fitted_remediation + rnorm(n, 0, 2 * noise))),
        Exploitability_Index = round(exploitability, 2),
        Dependency_Depth = dep_depth,
        Cluster_Group = "GAM Smooth Flow"
      )
      
      # --------------------------------------------------------------------------
      # Engine B: GMM (Gaussian Mixture Model) Based Simulation
      # --------------------------------------------------------------------------
    } else {
      k <- input$num_clusters
      testing_type <- c(rep("DAST", n_dast), rep("SCA", n_sca))
      
      cluster_assign <- sample(1:k, n, replace = TRUE)
      
      centers_cvss <- seq(2.0, 9.0, length.out = k)
      centers_days <- seq(5, 45, length.out = k)
      
      cvss_vec <- numeric(n)
      days_vec <- numeric(n)
      
      for (i in 1:n) {
        c_idx <- cluster_assign[i]
        cvss_vec[i] <- pmin(10, pmax(0, rnorm(1, mean = centers_cvss[c_idx], sd = 1.0 * noise)))
        days_vec[i] <- pmax(1, round(rnorm(1, mean = centers_days[c_idx], sd = 5.0 * noise)))
      }
      
      exploitability <- pmin(1.0, pmax(0.0, 0.09 * cvss_vec + rnorm(n, 0.1, 0.12 * noise)))
      dep_depth <- ifelse(testing_type == "SCA", sample(1:6, n, replace = TRUE), 0)
      
      df <- data.frame(
        Finding_ID = paste0("VULN-", 1000 + 1:n),
        Type = testing_type,
        CVSS_Score = round(cvss_vec, 1),
        Remediation_Days = days_vec,
        Exploitability_Index = round(exploitability, 2),
        Dependency_Depth = dep_depth,
        Cluster_Group = paste("Cluster", cluster_assign)
      )
    }
    
    # Severity Binning based on CVSS standard
    df <- df %>%
      mutate(
        Severity = case_when(
          CVSS_Score >= 9.0 ~ "Critical",
          CVSS_Score >= 7.0 ~ "High",
          CVSS_Score >= 4.0 ~ "Medium",
          TRUE ~ "Low"
        ),
        Severity = factor(Severity, levels = c("Low", "Medium", "High", "Critical"))
      )
    
    return(df)
  })
  
  # --------------------------------------------------------------------------
  # KPI Renderers
  # --------------------------------------------------------------------------
  output$kpi_total <- renderText({ nrow(simulated_data()) })
  
  output$kpi_critical <- renderText({
    df <- simulated_data()
    sum(df$Severity %in% c("High", "Critical"))
  })
  
  output$kpi_cvss <- renderText({
    mean(simulated_data()$CVSS_Score) %>% round(2)
  })
  
  output$kpi_remediation <- renderText({
    paste(round(mean(simulated_data()$Remediation_Days), 1), "Days")
  })
  
  # --------------------------------------------------------------------------
  # Plot Renderers
  # --------------------------------------------------------------------------
  
  # 1. CVSS Distribution Density Plot
  output$plot_cvss_dist <- renderPlotly({
    p <- ggplot(simulated_data(), aes(x = CVSS_Score, fill = Type)) +
      geom_density(alpha = 0.5) +
      scale_fill_manual(values = c("DAST" = "#1A365D", "SCA" = "#2B6CB0")) +
      theme_minimal(base_family = "Cambria") +
      labs(x = "CVSS Score", y = "Density", fill = "Type")
    ggplotly(p)
  })
  
  # 2. Model Fit Curve (GAM Smooth / GMM Clusters)
  output$plot_model_fit <- renderPlotly({
    df <- simulated_data()
    if (input$sim_method == "GAM") {
      p <- ggplot(df, aes(x = CVSS_Score, y = Remediation_Days, color = Type)) +
        geom_point(alpha = 0.6) +
        geom_smooth(method = "gam", formula = y ~ s(x, bs = "cs"), se = TRUE, color = "#C53030") +
        scale_color_manual(values = c("DAST" = "#1A365D", "SCA" = "#2B6CB0")) +
        theme_minimal(base_family = "Cambria") +
        labs(x = "CVSS Score", y = "Remediation Days")
    } else {
      p <- ggplot(df, aes(x = CVSS_Score, y = Remediation_Days, color = Cluster_Group)) +
        geom_point(alpha = 0.7, size = 2) +
        theme_minimal(base_family = "Cambria") +
        labs(x = "CVSS Score", y = "Remediation Days", color = "GMM Cluster")
    }
    ggplotly(p)
  })
  
  # 3. Severity Bar Chart
  output$plot_severity_bar <- renderPlotly({
    p <- ggplot(simulated_data(), aes(x = Severity, fill = Type)) +
      geom_bar(position = "dodge") +
      scale_fill_manual(values = c("DAST" = "#1A365D", "SCA" = "#2B6CB0")) +
      theme_minimal(base_family = "Cambria") +
      labs(x = "Severity Level", y = "Count")
    ggplotly(p)
  })
  
  # 4. SCA Dependency Depth Plot
  output$plot_sca_depth <- renderPlotly({
    df_sca <- simulated_data() %>% filter(Type == "SCA")
    if (nrow(df_sca) == 0) return(NULL)
    
    p <- ggplot(df_sca, aes(x = factor(Dependency_Depth), y = Exploitability_Index, fill = factor(Dependency_Depth))) +
      geom_boxplot(alpha = 0.7, show.legend = FALSE) +
      scale_fill_brewer(palette = "Blues") +
      theme_minimal(base_family = "Cambria") +
      labs(x = "Dependency Tree Depth", y = "Exploitability Index")
    ggplotly(p)
  })
  
  # --------------------------------------------------------------------------
  # Statistical Summary Tables
  # --------------------------------------------------------------------------
  
  output$table_summary_type <- renderTable({
    simulated_data() %>%
      group_by(Type) %>%
      summarise(
        Count = n(),
        `Mean CVSS` = round(mean(CVSS_Score), 2),
        `Std Dev CVSS` = round(sd(CVSS_Score), 2),
        `Mean Remediation Days` = round(mean(Remediation_Days), 1),
        `Avg Exploitability` = round(mean(Exploitability_Index), 2)
      )
  }, striped = TRUE, hover = TRUE, bordered = TRUE)
  
  output$table_summary_severity <- renderTable({
    simulated_data() %>%
      group_by(Severity) %>%
      summarise(
        Count = n(),
        `DAST Count` = sum(Type == "DAST"),
        `SCA Count` = sum(Type == "SCA"),
        `Mean CVSS` = round(mean(CVSS_Score), 2),
        `Max Remediation Days` = max(Remediation_Days)
      )
  }, striped = TRUE, hover = TRUE, bordered = TRUE)
  
  # --------------------------------------------------------------------------
  # Data Table Explorer
  # --------------------------------------------------------------------------
  output$raw_data_table <- renderDT({
    datatable(
      simulated_data(),
      options = list(pageLength = 10, autoWidth = TRUE),
      rownames = FALSE
    )
  })
  
  # --------------------------------------------------------------------------
  # CSV Download Handler
  # --------------------------------------------------------------------------
  output$btn_download <- downloadHandler(
    filename = function() {
      paste0("dast_sca_simulated_dataset_", input$sim_method, "_", Sys.Date(), ".csv")
    },
    content = function(file) {
      write.csv(simulated_data(), file, row.names = FALSE)
    }
  )
}

# Run Application
shinyApp(ui = ui, server = server)
