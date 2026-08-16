# ==============================================================================
# DEVSECOPS SAST ANALYTICS DASHBOARD & SYNTHETIC DATA GENERATOR (SHINY APP)
# ==============================================================================

library(shiny)
library(bslib)
library(dplyr)
library(tidyr)
library(ggplot2)
library(scales)
library(mgcv)   # GAM modeling
library(mclust) # GMM modeling
library(DT)     # Interactive tables

# ------------------------------------------------------------------------------
# 1. SYNTHETIC DATA GENERATION ENGINE (GAM & GMM)
# ------------------------------------------------------------------------------

generate_seed_data <- function() {
  set.seed(2026)
  n_seed <- 500
  projects <- c("Auth-Service", "Payment-API", "User-Portal", "Data-Pipeline")
  rules <- c("CWE-89: SQL Injection", "CWE-79: Cross-Site Scripting (XSS)", 
             "CWE-798: Hardcoded Secret", "CWE-78: Command Injection", 
             "CWE-22: Path Traversal", "CWE-200: Sensitive Info Exposure")
  severities <- c("Critical", "High", "Medium", "Low")
  statuses <- c("Open", "Fixed", "False Positive")
  
  data.frame(
    Project = sample(projects, n_seed, replace = TRUE, prob = c(0.3, 0.25, 0.25, 0.2)),
    CWE_Rule = sample(rules, n_seed, replace = TRUE),
    Severity = sample(severities, n_seed, replace = TRUE, prob = c(0.15, 0.30, 0.35, 0.20)),
    Status = sample(statuses, n_seed, replace = TRUE, prob = c(0.35, 0.50, 0.15)),
    Day_Offset = sample(0:120, n_seed, replace = TRUE),
    Remediation_Days = round(rnorm(n_seed, mean = 12, sd = 5))
  ) %>%
    mutate(
      Remediation_Days = ifelse(Remediation_Days < 1, 1, Remediation_Days),
      Severity_Num = as.numeric(factor(Severity, levels = c("Critical", "High", "Medium", "Low")))
    )
}

generate_sast_dataset <- function(n_samples = 250, method = "GAM", seed = 2026) {
  set.seed(seed)
  seed_df <- generate_seed_data()
  
  projects <- c("Auth-Service", "Payment-API", "User-Portal", "Data-Pipeline")
  rules <- c("CWE-89: SQL Injection", "CWE-79: Cross-Site Scripting (XSS)", 
             "CWE-798: Hardcoded Secret", "CWE-78: Command Injection", 
             "CWE-22: Path Traversal", "CWE-200: Sensitive Info Exposure")
  severities <- factor(c("Critical", "High", "Medium", "Low"), levels = c("Critical", "High", "Medium", "Low"))
  statuses <- c("Open", "Fixed", "False Positive")
  
  synth_df <- data.frame(
    Finding_ID = sprintf("SAST-%04d", 1:n_samples),
    Project = sample(projects, n_samples, replace = TRUE, prob = c(0.3, 0.25, 0.25, 0.2)),
    CWE_Rule = sample(rules, n_samples, replace = TRUE),
    Severity = sample(severities, n_samples, replace = TRUE, prob = c(0.15, 0.30, 0.35, 0.20)),
    Status = sample(statuses, n_samples, replace = TRUE, prob = c(0.35, 0.50, 0.15))
  ) %>%
    mutate(Severity_Num = as.numeric(Severity))
  
  if (method == "GAM") {
    gam_fit <- gam(Remediation_Days ~ s(Day_Offset, k = 5) + s(Severity_Num, k = 3), data = seed_df)
    
    synth_df$Day_Offset <- sample(0:120, n_samples, replace = TRUE)
    pred_means <- predict(gam_fit, newdata = synth_df)
    sigma_est <- sqrt(gam_fit$sig2)
    
    synth_df$Remediation_Days <- round(rnorm(n_samples, mean = pred_means, sd = sigma_est))
    
  } else if (method == "GMM") {
    gmm_fit <- Mclust(seed_df[, c("Day_Offset", "Remediation_Days")], G = 3, verbose = FALSE)
    simulated_gmm <- sim(gmm_fit$modelName, gmm_fit$parameters, n_samples)
    
    synth_df$Day_Offset <- round(simulated_gmm$data[, 1])
    synth_df$Remediation_Days <- round(simulated_gmm$data[, 2])
  }
  
  synth_df <- synth_df %>%
    mutate(
      Day_Offset = pmax(0, pmin(120, Day_Offset)),
      Remediation_Days = pmax(1, Remediation_Days),
      Discovery_Date = as.Date("2026-01-01") + Day_Offset,
      Remediation_Days = ifelse(Status == "Fixed", Remediation_Days, NA),
      Resolved_Date = ifelse(Status == "Fixed", as.character(Discovery_Date + Remediation_Days), NA)
    ) %>%
    select(Finding_ID, Project, CWE_Rule, Severity, Status, Discovery_Date, Remediation_Days, Resolved_Date)
  
  return(synth_df)
}

# ------------------------------------------------------------------------------
# 2. UI SPECIFICATION (CAMBRIA FONT & DASHBOARD LAYOUT)
# ------------------------------------------------------------------------------

ui <- fluidPage(
  theme = bs_theme(version = 5, bootswatch = "flatly", primary = "#2c3e50"),
  
  tags$head(
    tags$style(HTML("
      * {
        font-family: 'Cambria', 'Georgia', serif !important;
      }
      body {
        background-color: #f4f6f9;
      }
      .metric-card {
        background: #ffffff;
        border-radius: 8px;
        padding: 18px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        border-top: 4px solid #2c3e50;
        text-align: center;
      }
      .metric-title {
        font-size: 0.85rem;
        color: #7f8c8d;
        text-transform: uppercase;
        font-weight: bold;
        letter-spacing: 0.5px;
      }
      .metric-value {
        font-size: 1.8rem;
        font-weight: bold;
        color: #2c3e50;
        margin-top: 5px;
      }
      .card-box {
        background: #ffffff;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        margin-bottom: 20px;
      }
    "))
  ),
  
  titlePanel(
    div(
      h2("DevSecOps SAST Analytics Dashboard", style = "font-weight: bold; color: #2c3e50;"),
      h5("Synthetic Vulnerability Dataset Generator & Pipeline Metrics", style = "color: #7f8c8d;")
    )
  ),
  
  sidebarLayout(
    sidebarPanel(
      width = 3,
      div(
        class = "card-box",
        h4("Data Generation Parameters", style = "font-weight: bold;"),
        hr(),
        sliderInput("n_samples", "Sample Size (N Findings):", min = 50, max = 1000, value = 250, step = 50),
        radioButtons("method", "Generative Algorithm:", 
                     choices = c("Generalized Additive Model (GAM)" = "GAM", 
                                 "Gaussian Mixture Model (GMM)" = "GMM"), 
                     selected = "GAM"),
        numericInput("seed", "Random Seed:", value = 2026, min = 1, max = 99999),
        actionButton("generate_btn", "Generate Dataset", class = "btn-primary w-100", style = "font-weight: bold;"),
        hr(),
        downloadButton("download_csv", "Download Dataset (CSV)", class = "btn-success w-100")
      )
    ),
    
    mainPanel(
      width = 9,
      
      fluidRow(
        column(2, div(class = "metric-card", div(class = "metric-title", "Total Findings"), div(class = "metric-value", textOutput("kpi_total")))),
        column(2, div(class = "metric-card", div(class = "metric-title", "Critical Flaws"), div(class = "metric-value", textOutput("kpi_critical")))),
        column(2, div(class = "metric-card", div(class = "metric-title", "Open Issues"), div(class = "metric-value", textOutput("kpi_open")))),
        column(3, div(class = "metric-card", div(class = "metric-title", "False Positive Rate"), div(class = "metric-value", textOutput("kpi_fp_rate")))),
        column(3, div(class = "metric-card", div(class = "metric-title", "MTTR (Mean Time)"), div(class = "metric-value", textOutput("kpi_mttr"))))
      ),
      br(),
      
      tabsetPanel(
        type = "tabs",
        
        tabPanel(
          "Dashboard Plots",
          br(),
          div(class = "card-box", plotOutput("plot_severity", height = "300px")),
          div(class = "card-box", plotOutput("plot_remediation", height = "300px")),
          div(class = "card-box", plotOutput("plot_triage", height = "340px"))
        ),
        
        tabPanel(
          "Summary Tables",
          br(),
          div(
            class = "card-box",
            h4("Table 1: Severity Distribution by Project Component", style = "font-weight: bold;"),
            tableOutput("table_project_matrix")
          ),
          div(
            class = "card-box",
            h4("Table 2: Vulnerability Triage Status by CWE Rule", style = "font-weight: bold;"),
            tableOutput("table_cwe_matrix")
          )
        ),
        
        tabPanel(
          "Raw Data Explorer",
          br(),
          div(
            class = "card-box",
            DTOutput("raw_data_table")
          )
        )
      )
    )
  )
)

# ------------------------------------------------------------------------------
# 3. SERVER LOGIC
# ------------------------------------------------------------------------------

server <- function(input, output, session) {
  
  # Reactive Dataset Generator
  dataset <- eventReactive(input$generate_btn, {
    generate_sast_dataset(
      n_samples = input$n_samples, 
      method = input$method, 
      seed = input$seed
    )
  }, ignoreNULL = FALSE)
  
  # KPI Calculations
  output$kpi_total <- renderText({ nrow(dataset()) })
  output$kpi_critical <- renderText({ sum(dataset()$Severity == "Critical") })
  output$kpi_open <- renderText({ sum(dataset()$Status == "Open") })
  
  output$kpi_fp_rate <- renderText({
    fp <- sum(dataset()$Status == "False Positive")
    sprintf("%.1f%%", (fp / nrow(dataset())) * 100)
  })
  
  output$kpi_mttr <- renderText({
    mttr <- mean(dataset()$Remediation_Days, na.rm = TRUE)
    sprintf("%.1f Days", mttr)
  })
  
  # Plot 1: Severity Profile by Project
  output$plot_severity <- renderPlot({
    sev_colors <- c("Critical" = "#d9534f", "High" = "#f0ad4e", "Medium" = "#5bc0de", "Low" = "#5cb85c")
    
    ggplot(dataset(), aes(x = Project, fill = Severity)) +
      geom_bar(position = "dodge", color = "black", linewidth = 0.2) +
      scale_fill_manual(values = sev_colors) +
      theme_minimal(base_family = "Cambria") +
      theme(
        text = element_text(family = "Cambria"),
        plot.title = element_text(face = "bold", size = 14),
        axis.title = element_text(face = "bold")
      ) +
      labs(title = "1. Vulnerability Severity Distribution per Microservice",
           x = "Project / Service", y = "Finding Count")
  })
  
  # Plot 2: Remediation Velocity / MTTR Density
  output$plot_remediation <- renderPlot({
    sev_colors <- c("Critical" = "#d9534f", "High" = "#f0ad4e", "Medium" = "#5bc0de", "Low" = "#5cb85c")
    fixed_data <- dataset() %>% filter(Status == "Fixed")
    
    ggplot(fixed_data, aes(x = Remediation_Days, fill = Severity)) +
      geom_density(alpha = 0.6) +
      scale_fill_manual(values = sev_colors) +
      theme_minimal(base_family = "Cambria") +
      theme(
        text = element_text(family = "Cambria"),
        plot.title = element_text(face = "bold", size = 14),
        axis.title = element_text(face = "bold")
      ) +
      labs(title = "2. Remediation Velocity (Mean Time to Repair Density)",
           x = "Days to Resolve", y = "Density")
  })
  
  # Plot 3: Triage Proportions by Rule
  output$plot_triage <- renderPlot({
    status_colors <- c("Open" = "#d9534f", "Fixed" = "#5cb85c", "False Positive" = "#aaaaaa")
    
    ggplot(dataset(), aes(x = CWE_Rule, fill = Status)) +
      geom_bar(position = "fill", color = "black", linewidth = 0.2) +
      scale_fill_manual(values = status_colors) +
      scale_y_continuous(labels = percent) +
      coord_flip() +
      theme_minimal(base_family = "Cambria") +
      theme(
        text = element_text(family = "Cambria"),
        plot.title = element_text(face = "bold", size = 14),
        axis.title = element_text(face = "bold")
      ) +
      labs(title = "3. Flaw Triage Ratio (Fixed vs Open vs False Positives)",
           x = "CWE Security Rule", y = "Proportion")
  })
  
  # Table 1: Severity Matrix
  output$table_project_matrix <- renderTable({
    dataset() %>%
      group_by(Project, Severity) %>%
      tally() %>%
      pivot_wider(names_from = Severity, values_from = n, values_fill = 0)
  }, striped = TRUE, hover = TRUE, bordered = TRUE)
  
  # Table 2: CWE Matrix
  output$table_cwe_matrix <- renderTable({
    dataset() %>%
      group_by(CWE_Rule, Status) %>%
      tally() %>%
      pivot_wider(names_from = Status, values_from = n, values_fill = 0)
  }, striped = TRUE, hover = TRUE, bordered = TRUE)
  
  # Interactive DT Table
  output$raw_data_table <- renderDT({
    datatable(
      dataset(),
      options = list(pageLength = 10, autoWidth = TRUE),
      rownames = FALSE
    )
  })
  
  # CSV Download Handler
  output$download_csv <- downloadHandler(
    filename = function() {
      sprintf("sast_synthetic_dataset_%s_%s.csv", tolower(input$method), Sys.Date())
    },
    content = function(file) {
      write.csv(dataset(), file, row.names = FALSE)
    }
  )
}

# ------------------------------------------------------------------------------
# 4. LAUNCH APP
# ------------------------------------------------------------------------------
shinyApp(ui = ui, server = server)