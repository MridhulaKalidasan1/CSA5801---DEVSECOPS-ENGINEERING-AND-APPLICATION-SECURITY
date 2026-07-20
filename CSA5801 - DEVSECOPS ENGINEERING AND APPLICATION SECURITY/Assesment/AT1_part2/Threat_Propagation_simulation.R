# ==============================================================================
# PHASE 1: SYNTHETIC DATA GENERATION VIA NATIVE MATHEMATICAL SYNTHESIS
# ==============================================================================
cat("--- PHASE 1: Native Base R Data Generation Starting ---\n")

set.seed(42)
n_records <- 1000

# 1. Base Structure: Segmented enterprise network architecture
node_ids <- 1:n_records
zones <- c("DMZ", "Corporate", "Data Center", "Endpoint Zone")
network_layer <- sample(zones, n_records, replace = TRUE, prob = c(0.1, 0.4, 0.2, 0.3))

# 2. Mathematical GAM Engine Equivalent (Deterministic Non-linear Modeling)
node_age_days <- runif(n_records, 1, 365)
# Replicating smooth spline curves using mathematical transformations
smooth_vuln_trend <- 0.35 * sin(node_age_days / 45) + 0.45 * cos(node_age_days / 180)^2
vuln_noise <- rnorm(n_records, mean = 0, sd = 0.08)
raw_vulnerability <- smooth_vuln_trend + vuln_noise

# 3. Mathematical GMM Engine Equivalent (Multi-Modal Distribution Synthesis)
comp <- sample(1:3, n_records, replace = TRUE, prob = c(0.5, 0.3, 0.2))
traffic_volume <- numeric(n_records)
privilege_level <- numeric(n_records)

# Cluster 1: Low footprint endpoints (High density)
traffic_volume[comp == 1] <- rnorm(sum(comp == 1), mean = 22, sd = 4)
privilege_level[comp == 1] <- rnorm(sum(comp == 1), mean = 1.8, sd = 0.4)

# Cluster 2: Internet-facing DMZ arrays (High traffic, low domain access)
traffic_volume[comp == 2] <- rnorm(sum(comp == 2), mean = 88, sd = 8)
privilege_level[comp == 2] <- rnorm(sum(comp == 2), mean = 3.2, sd = 0.6)

# Cluster 3: Privileged core assets (Medium traffic, max access authorization)
traffic_volume[comp == 3] <- rnorm(sum(comp == 3), mean = 55, sd = 10)
privilege_level[comp == 3] <- rnorm(sum(comp == 3), mean = 8.7, sd = 0.9)

# Core Vector Normalization Function (Zero Dependencies Scales Replacement)
native_scale <- function(x, target_min, target_max) {
  (x - min(x)) / (max(x) - min(x)) * (target_max - target_min) + target_min
}

# Consolidate into the Primary Asset Registry Matrix
network_df <- data.frame(
  NodeID = node_ids,
  Zone = network_layer,
  Vulnerability = native_scale(raw_vulnerability, 0.05, 0.95),
  TrafficLoad = native_scale(traffic_volume, 1, 100),
  Privilege = native_scale(privilege_level, 1, 10),
  InfectionStatus = "Healthy",
  TimeInfected = NA_real_,
  stringsAsFactors = FALSE
)

cat("Success: Generated asset matrix dataframe.\n")
print(summary(network_df))

# Visualizing Multi-modal structure using Native Base Graphics
zone_colors <- c("DMZ"="#E41A1C", "Corporate"="#377EB8", "Data Center"="#984EA3", "Endpoint Zone"="#4DAF4A")
plot(network_df$TrafficLoad, network_df$Privilege, 
     col = zone_colors[network_df$Zone], pch = 20, main = "Asset Distribution Profile Topology",
     xlab = "System Traffic Load Index", ylab = "Privilege Level Score")
legend("topright", legend = names(zone_colors), col = zone_colors, pch = 20, bty = "n")

# ==============================================================================
# PHASE 2: PROPAGATION PREPROCESSING & FACTOR SETUP
# ==============================================================================
cat("\n--- PHASE 2: Compiling Threat Propagation Metrics ---\n")

# Setup network bandwidth capacity threshold limitations
network_df$OutboundBandwidth <- network_df$TrafficLoad * 0.12

# Map security threat evaluation criteria vectors
get_threat_matrix <- function(vector_type) {
  if (vector_type == "external") {
    # External: High energy, restricted heavily by network boundaries
    list(energy = 90, strength = 0.70, power = 0.55, mutation = 0.06, speed = 1.3, boundary = 0.88)
  } else {
    # Internal: Low initial energy footprint, bypasses cross-zone security controls
    list(energy = 45, strength = 0.95, power = 0.80, mutation = 0.18, speed = 0.7, boundary = 0.12)
  }
}

# ==============================================================================
# PHASE 3: DISCRETE EVENT SIMULATION ENGINE
# ==============================================================================
cat("\n--- PHASE 3: Executing Discrete Event Propagation Simulation Loop ---\n")

execute_propagation_engine <- function(input_network, mode) {
  threat <- get_threat_matrix(mode)
  runtime_data <- input_network
  
  # Deploy initial vectors based on authorization posture profiles
  if(mode == "external") {
    patient_zero <- sample(which(runtime_data$Zone == "DMZ"), 3)
  } else {
    patient_zero <- sample(which(runtime_data$Zone == "Corporate"), 1)
  }
  
  runtime_data$InfectionStatus[patient_zero] <- "Infected"
  runtime_data$TimeInfected[patient_zero] <- 0
  
  clock_tick <- 0
  max_ticks <- 40
  remaining_energy <- threat$energy
  
  while(sum(runtime_data$InfectionStatus == "Infected") > 0 && clock_tick < max_ticks && remaining_energy > 0) {
    current_hosts <- runtime_data$NodeID[runtime_data$InfectionStatus == "Infected"]
    susceptible_hosts <- which(runtime_data$InfectionStatus == "Healthy")
    
    if(length(susceptible_hosts) == 0) break
    
    for(host in current_hosts) {
      host_zone <- runtime_data$Zone[runtime_data$NodeID == host]
      
      # Select random downstream lateral movement targets
      targets <- sample(susceptible_hosts, min(4, length(susceptible_hosts)))
      
      for(target in targets) {
        target_zone <- runtime_data$Zone[target]
        
        # Calculate cross-boundary penalty constraints
        boundary_barrier <- if(host_zone != target_zone) threat$boundary else 0
        
        # Determine transmission compromise factor
        compromise_probability <- runtime_data$Vulnerability[target] * threat$strength * (1 - boundary_barrier)
        
        if(runif(1) < compromise_probability) {
          runtime_data$InfectionStatus[target] <- "Infected"
          runtime_data$TimeInfected[target] <- clock_tick + (runif(1) * threat$speed)
          
          # Compute dynamic mutation footprint shifts
          threat$strength <- threat$strength * (1 + runif(1, -threat$mutation, threat$mutation))
          # Deplete threat structural energy resources based on asset resistance
          remaining_energy <- remaining_energy - (runtime_data$Privilege[target] * 0.04)
        }
      }
    }
    clock_tick <- clock_tick + 1
  }
  return(runtime_data)
}

# Run execution engines
external_simulation_output <- execute_propagation_engine(network_df, "external")
internal_simulation_output <- execute_propagation_engine(network_df, "internal")

# ==============================================================================
# ANALYTICAL SUMMARY & EVALUATION OUTPUTS
# ==============================================================================
cat("\n--- STAGE VISUALIZATION AND METRIC SUMMARIES ---\n")

ext_total <- sum(external_simulation_output$InfectionStatus == "Infected")
int_total <- sum(internal_simulation_output$InfectionStatus == "Infected")
ext_avg_time <- mean(external_simulation_output$TimeInfected, na.rm = TRUE)
int_avg_time <- mean(internal_simulation_output$TimeInfected, na.rm = TRUE)

summary_frame <- data.frame(
  Threat_Vector = c("External (Malware/Virus)", "Internal (Rogue Employee/Privilege Misuse)"),
  Total_Compromised_Nodes = c(ext_total, int_total),
  Mean_Infection_Velocity = c(round(ext_avg_time, 2), round(int_avg_time, 2))
)
print(summary_frame)

# Generate tracking plots via Native Base Graphical Matrix Engine
old_par <- par(mfrow = c(1, 2))

hist(external_simulation_output$TimeInfected, breaks = 12, col = "#FF7F00", border = "white",
     main = "External Threat Curve", xlab = "Simulation Clock (Ticks)", ylab = "Host Accumulation Rate")

hist(internal_simulation_output$TimeInfected, breaks = 12, col = "#E41A1C", border = "white",
     main = "Internal Threat Curve", xlab = "Simulation Clock (Ticks)", ylab = "Host Accumulation Rate")

par(old_par)
cat("\n--- Pure Native Base R Simulation Execution Complete ---\n")

