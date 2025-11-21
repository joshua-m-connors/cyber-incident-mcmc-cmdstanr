#!/usr/bin/env Rscript
# Cyber Incident Risk Model with MITRE ATT&CK + FAIR (cmdstanr)
# Version: v1.1.2
# -----------------------------------------------------------------------------
# WHAT THIS DOES
#   • Uses cmdstanr to fit a prior-driven Bayesian model for:
#       - Annual attempt rate λ ~ LogNormal(mu_lambda, sigma_lambda)
#       - Per-tactic success probabilities ~ Beta(alpha_t, beta_t)
#   • Priors are derived from tactic-level control strengths aggregated by
#     `mitre_control_strength_dashboard.R` (Filtered or Full mode).
#   • Posterior predictive simulates end-to-end attacker chains with retries,
#     detection, and fallback; then draws FAIR-style loss categories.
#   • Outputs CSVs (summary + optional per-draw) and PNG charts:
#       - Histograms with 5/50/95 percentile lines
#       - Loss Exceedance Curve (log scale, with log(0) guard)
#
# USAGE (examples)
#   Rscript cyber_incident_cmdstanr.R \
#     --dataset enterprise-attack.json \
#     --strengths mitigation_control_strengths.csv \
#     --samples 4000 --chains 4 --tune 1000 --seed 42
#
#   Rscript cyber_incident_cmdstanr.R --summary-only --no-plot
#   Rscript cyber_incident_cmdstanr.R --output-dir ./output_custom
# -----------------------------------------------------------------------------

suppressPackageStartupMessages({
  # --- Ensure working directory is the same as the script's directory ---
  library(cmdstanr)
  library(posterior)
  library(dplyr)
  library(readr)
  library(ggplot2)
  library(scales)
  library(jsonlite)
  library(stringr)
  library(optparse)
})

`%||%` <- function(a,b){ if (is.null(a)) b else a }

# ================================
# USER-ADJUSTABLE SETTINGS (common)
# ================================
# Credible interval for annual attempt rate λ (FAIR TEF proxy).
# These are interpreted as the 5th and 95th percentiles for attempts/year.
CI_MIN_FREQ <- 4           # e.g., once per quarter
CI_MAX_FREQ <- 24          # e.g., twice per month

# Threat capability: multiplicative drift applied to per-stage success probs.
THREAT_CAPABILITY_STOCHASTIC <- TRUE
THREAT_CAPABILITY_RANGE <- c(0.4, 0.95)   # [low, high] lift applied

# Impact reduction multipliers when gating conditions pass (from dashboard):
# - Backup reduces Productivity + Response/Containment
# - Encryption reduces Regulatory/Legal + Reputation/Competitive
BACKUP_IMPACT_MULT  <- 0.60
ENCRYPT_IMPACT_MULT <- 0.50
STOCHASTIC_IMPACT_REDUCTION <- TRUE  # sample within min/max each iteration

# Loss category parameterization (lognormal via q5/q95) and occasional
loss_categories <- c("Productivity","ResponseContainment","RegulatoryLegal","ReputationCompetitive")
loss_q5_q95 <- list(Productivity=c(1000,200000), ResponseContainment=c(10000,1000000),
                    RegulatoryLegal=c(0,3000000), ReputationCompetitive=c(0,5000000))

# Money formatting
PLOT_IN_MILLIONS <- TRUE  # TRUE -> show $M, FALSE -> raw dollars

# =================================
# USER-ADJUSTABLE SETTINGS (advanced)
# =================================
# Attacker adaptability across retries at a stage.
ADAPTABILITY_STOCHASTIC <- TRUE
ADAPTABILITY_RANGE <- c(0.3, 0.9)   # adaptive gain range
ADAPTABILITY_MODE <- "linear"     # "logistic" or "linear"
ADAPTABILITY_EFFECT_SCALE <- 1.0    # if MODE == "linear"

# Detection & fallback dynamics.
MAX_RETRIES_PER_STAGE <- 3
DETECT_BASE <- 0.01
DETECT_INC_PER_RETRY <- 0.03
FALLBACK_PROB <- 0.25
MAX_FALLBACKS_PER_CHAIN <- 3

# Loss category parameterization for
# heavy-tail bumps (bounded Pareto) for Regulatory & Reputation.
pareto_defaults <- list(RegulatoryLegal=list(xm=50000, alpha=3.5),
                        ReputationCompetitive=list(xm=100000, alpha=2.75))

# ----------------------------------------------------------------------------
# Helpers: output directory, distributions, formatting
# ----------------------------------------------------------------------------
make_output_dir <- function(prefix="output", override=NULL, quiet=FALSE){
  out_dir <- override
  if (is.null(out_dir) || !nzchar(out_dir)) {
    out_dir <- file.path(getwd(), paste0(prefix, "_", format(Sys.Date(), "%Y-%m-%d")))
  }
  if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
  if (!quiet) message("📁 Output directory: ", out_dir)
  out_dir
}

Z_90 <- 1.645
# Replace the current version with this one
lognormal_from_q5_q95 <- function(q5, q95){
  q5  <- max(q5, 1.0)         # <-- revert to 1.0 to match Python
  q95 <- max(q95, q5 * 1.0001)
  ln5 <- log(q5); ln95 <- log(q95)
  sigma <- (ln95 - ln5) / (2 * Z_90)
  mu    <- 0.5 * (ln5 + ln95)
  c(mu, sigma)
}

tmp <- sapply(names(loss_q5_q95), function(nm) lognormal_from_q5_q95(loss_q5_q95[[nm]][1], loss_q5_q95[[nm]][2]))
cat_mu <- tmp[1,]; cat_sigma <- tmp[2,]

rbounded_pareto <- function(n, xm, alpha, cap_quant=0.95){
  u <- runif(n, min=0.001, max=0.999)
  draw <- xm * (1 - u)^(-1/alpha)
  cap <- xm * (1 - cap_quant)^(-1/alpha)
  pmin(draw, cap)
}

fmt_money <- function(x){
  if (PLOT_IN_MILLIONS) {
    dollar(x/1e6, suffix="M")
  } else {
    dollar(x)
  }
}

# ----------------------------------------------------------------------------
# Dependency: load tactic strengths via dashboard script
# ----------------------------------------------------------------------------
source_if_exists <- function(path){
  if (file.exists(path)) source(path, local = TRUE) else stop("Required file not found: ", path, call.=FALSE)
}

# ---- Dependency: get tactic strengths via dashboard helper -------------------
# v1.1.3 FIX — forcibly clear any stale local versions before sourcing globally.
get_strengths <- function(dataset="enterprise-attack.json",
                          csv="mitigation_control_strengths.csv",
                          outdir=NULL, quiet=FALSE,
                          relevance_file="technique_relevance.csv") {
  
  # Drop any previously loaded local version of the function
  if (exists("get_mitre_tactic_strengths", envir = .GlobalEnv)) {
    rm("get_mitre_tactic_strengths", envir = .GlobalEnv)
  }
  
  # Source dashboard script fresh into the global environment
  oldflag <- getOption("MITRE_DASH_IMPORT")
  options(MITRE_DASH_IMPORT = TRUE)
  on.exit(options(MITRE_DASH_IMPORT = oldflag), add = TRUE)
  
  source("mitre_control_strength_dashboard.R", local = FALSE)
  
  # Retrieve filtered results directly from the global environment
  res <- .GlobalEnv$get_mitre_tactic_strengths(
    dataset_path  = dataset,
    csv_path      = csv,
    use_relevance = TRUE,
    relevance_file = relevance_file,
    build_figure  = FALSE,
    output_dir    = outdir,
    quiet         = quiet
  )
  
  # Defensive fallback in case filtering yields 0 included tactics
  if (is.null(res) || length(res$included_tactics) == 0) {
    warning("⚠️ No tactics returned from dashboard — forcing fallback to Full mode.")
    res <- .GlobalEnv$get_mitre_tactic_strengths(
      dataset_path  = dataset,
      csv_path      = csv,
      use_relevance = FALSE,
      build_figure  = FALSE,
      output_dir    = outdir,
      quiet         = quiet
    )
  }
  
  # Compact tactic -> (min,max) map for downstream priors
  stage_map <- setNames(lapply(res$included_tactics, function(tac){
    c(res$stage_map[[tac]]$min_strength/100,
      res$stage_map[[tac]]$max_strength/100)
  }), res$included_tactics)
  
  list(
    tactics         = res$included_tactics,
    stage_map       = stage_map,
    impact_controls = as.list(res$impact_controls),
    output_dir      = res$output_dir,
    mode            = res$relevance_metadata$mode
  )
}

# ----------------------------------------------------------------------------
# Convert control strength block -> success probability Beta prior
# ----------------------------------------------------------------------------
success_interval_from_control <- function(block_lo, block_hi){
  block_lo <- pmin(pmax(block_lo,0.0),0.95)
  block_hi <- pmin(pmax(block_hi,0.0),0.95)
  lo <- 1.0 - block_hi
  hi <- 1.0 - block_lo
  if (lo > hi) { tmp <- lo; lo <- hi; hi <- tmp }
  c(lo,hi)
}

beta_from_interval <- function(lo,hi,strength=50.0){
  mu <- 0.5*(lo+hi); k <- max(2.0, strength)
  a <- max(1e-3, mu*k); b <- max(1e-3, (1-mu)*k)
  c(a,b)
}

build_beta_priors <- function(stage_map, tactics){
  a <- b <- numeric(length(tactics))
  for (i in seq_along(tactics)){
    ints <- success_interval_from_control(stage_map[[tactics[i]]][1], stage_map[[tactics[i]]][2])
    ab <- beta_from_interval(ints[1], ints[2], strength=50.0)
    a[i] <- ab[1]; b[i] <- ab[2]
  }
  list(alpha=a,beta=b)
}

# ----------------------------------------------------------------------------
# Inline Stan model (simple conjugate-like structure)
# ----------------------------------------------------------------------------
stan_code <- "
data {
  int<lower=1> K;
  vector<lower=0>[K] alpha;
  vector<lower=0>[K] beta;
  real mu_lambda;
  real<lower=0> sigma_lambda;
}
parameters {
  real<lower=0> lambda_rate;
  vector<lower=0,upper=1>[K] success_probs;
}
model {
  lambda_rate ~ lognormal(mu_lambda, sigma_lambda);
  success_probs ~ beta(alpha, beta);
}
"

# ----------------------------------------------------------------------------
# Attacker progression with retries/detection/fallback
# ----------------------------------------------------------------------------
simulate_attacker_path <- function(success_probs){
  # success_probs: base per-stage success probabilities for this draw (already clamped [0,1])
  if (length(success_probs) == 0L) return(FALSE)
  
  n_stages <- length(success_probs)
  i <- 1L
  fallback_count <- 0L
  
  while (i >= 1L && i <= n_stages) {
    p_base <- min(1.0, max(0.0, success_probs[i]))
    
    retry <- 0L
    stage_cleared <- FALSE
    
    while (retry < MAX_RETRIES_PER_STAGE && !stage_cleared) {
      retry <- retry + 1L
      
      # Detection grows with retries
      detect_cur <- min(1.0, DETECT_BASE + DETECT_INC_PER_RETRY * (retry - 1L))
      
      # Adaptability can only soften detection a bit — it NEVER increases p_base
      if (ADAPTABILITY_STOCHASTIC) {
        adapt <- runif(1, ADAPTABILITY_RANGE[1], ADAPTABILITY_RANGE[2])
      } else {
        adapt <- mean(ADAPTABILITY_RANGE)
      }
      if (ADAPTABILITY_MODE == "linear") {
        detect_eff <- min(1.0, detect_cur * (1.0 - 0.5 * adapt))
      } else if (ADAPTABILITY_MODE == "logistic") {
        detect_eff <- min(1.0, detect_cur / (1.0 + 2.0 * adapt))
      } else {
        detect_eff <- detect_cur
      }
      
      # Detection reduces success probability; we do NOT inflate success on retries
      p_eff <- max(0.0, p_base * (1.0 - detect_eff))
      
      # Bernoulli for this stage
      if (runif(1) < p_eff) {
        stage_cleared <- TRUE
      } else {
        # On a failed try, a detection event can still kill the chain
        if (runif(1) < detect_eff) return(FALSE)
        # else: silent fail, try again (up to MAX_RETRIES_PER_STAGE)
      }
    }
    
    if (stage_cleared) {
      i <- i + 1L  # move to next stage
    } else {
      # Stage not cleared after retries → maybe fallback back one step
      if (runif(1) < FALLBACK_PROB && fallback_count < MAX_FALLBACKS_PER_CHAIN) {
        fallback_count <- fallback_count + 1L
        i <- max(1L, i - 1L)
      } else {
        return(FALSE)  # chain fails
      }
    }
  }
  
  i > n_stages  # TRUE if all stages cleared
}

# ----------------------------------------------------------------------------
# Posterior predictive simulation (annual loss)
# ----------------------------------------------------------------------------
simulate_posterior_predictive <- function(draws_lambda, succ_mat, tactics, impact_controls){
  n <- length(draws_lambda); losses <- numeric(n); successes <- integer(n)
  prod_losses <- resp_losses <- reg_losses <- rep_losses <- numeric(n)

  get_ic <- function(name, idx){
    v <- impact_controls[[name]]
    if (is.null(v)) return(0.0)
    as.numeric(v[idx])/100.0
  }
  b_lo <- get_ic("Data Backup","min_strength")
  b_hi <- get_ic("Data Backup","max_strength")
  b_mean <- get_ic("Data Backup","mean_strength")
  e_lo <- get_ic("Encrypt Sensitive Information","min_strength")
  e_hi <- get_ic("Encrypt Sensitive Information","max_strength")
  e_mean <- get_ic("Encrypt Sensitive Information","mean_strength")

  # =========================================================
  # === Diagnostic Block 2: Capability / Adaptability check ==
  # =========================================================
  cat("\n--- SIMULATION CONFIG CHECK ---\n")
  cat("THREAT_CAPABILITY_RANGE:", paste(THREAT_CAPABILITY_RANGE, collapse = ", "), "\n")
  cat("ADAPTABILITY_RANGE:", paste(ADAPTABILITY_RANGE, collapse = ", "), "\n")
  cat("Adaptability mode:", ADAPTABILITY_MODE, "\n")
  # =========================================================
  
  for (i in seq_len(n)) {
    lam <- draws_lambda[i]; attempts <- rpois(1, lam); succ_count <- 0L
    prod_acc <- resp_acc <- reg_acc <- rep_acc <- 0.0; total_loss <- 0.0

    tc <- if (THREAT_CAPABILITY_STOCHASTIC) runif(1, THREAT_CAPABILITY_RANGE[1], THREAT_CAPABILITY_RANGE[2]) else mean(THREAT_CAPABILITY_RANGE)
    if (STOCHASTIC_IMPACT_REDUCTION) {
      backup_s  <- if (b_hi > b_lo) runif(1,b_lo,b_hi) else b_lo
      encrypt_s <- if (e_hi > e_lo) runif(1,e_lo,e_hi) else e_lo
    } else {
      backup_s <- b_mean; encrypt_s <- e_mean
    }

    for (j in seq_len(attempts)) {
      stage_success_probs <- as.numeric(succ_mat[i, ])
      if (length(stage_success_probs) == 0) next
      stage_success_probs <- pmin(pmax(stage_success_probs, 0.0), 1.0)
      
      if (simulate_attacker_path(stage_success_probs)) {
        prod <- rlnorm(1, meanlog = cat_mu[1], sdlog = cat_sigma[1])
        resp <- rlnorm(1, meanlog = cat_mu[2], sdlog = cat_sigma[2])
        reg  <- rlnorm(1, meanlog = cat_mu[3], sdlog = cat_sigma[3])
        rep  <- rlnorm(1, meanlog = cat_mu[4], sdlog = cat_sigma[4])
        # occasional heavy tails
        if (runif(1) < 0.025) reg <- max(reg, rbounded_pareto(1, xm = pareto_defaults$RegulatoryLegal$xm, alpha = pareto_defaults$RegulatoryLegal$alpha))
        if (runif(1) < 0.015) rep <- max(rep, rbounded_pareto(1, xm = pareto_defaults$ReputationCompetitive$xm, alpha = pareto_defaults$ReputationCompetitive$alpha))
        # impact reductions
        # impact reductions
        # backup_s and encrypt_s are already 0–1 from get_ic() above — do NOT divide again
        if (backup_s > 0)  {
          scale <- max(0.0, 1.0 - backup_s * BACKUP_IMPACT_MULT)
          prod <- prod*scale; resp <- resp*scale
        }
        if (encrypt_s > 0) {
          scale <- max(0.0, 1.0 - encrypt_s * ENCRYPT_IMPACT_MULT)
          reg <- reg*scale; rep <- rep*scale
        }
                if (backup_s > 0)  { scale <- max(0.0, 1.0 - backup_s * BACKUP_IMPACT_MULT); prod <- prod*scale; resp <- resp*scale }
        if (encrypt_s > 0) { scale <- max(0.0, 1.0 - encrypt_s * ENCRYPT_IMPACT_MULT); reg <- reg*scale; rep <- rep*scale }
        prod_acc <- prod_acc + prod; resp_acc <- resp_acc + resp; reg_acc <- reg_acc + reg; rep_acc <- rep_acc + rep
        total_loss <- total_loss + (prod + resp + reg + rep)
        succ_count <- succ_count + 1L
      }
    }
    losses[i] <- total_loss; successes[i] <- succ_count
    prod_losses[i] <- prod_acc; resp_losses[i] <- resp_acc; reg_losses[i] <- reg_acc; rep_losses[i] <- rep_acc
  }
  list(losses=losses, successes=successes,
       per_cat=list(Productivity=prod_losses, ResponseContainment=resp_losses, RegulatoryLegal=reg_losses, ReputationCompetitive=rep_losses))
}

# ----------------------------------------------------------------------------
# Plotting: percentile lines; LEC with log(0) guard
# ----------------------------------------------------------------------------
add_percentile_lines <- function(p, values, color="red"){
  qs <- quantile(values, probs = c(0.05, 0.5, 0.95), na.rm=TRUE)
  p + geom_vline(xintercept = qs, linetype = "dashed", color = color) +
      annotate("text", x = qs, y = 0, label = paste0(names(qs), ": ", round(qs, 3)),
               vjust = -0.5, hjust = 0, angle = 90, color = color, size = 3)
}

render_plots <- function(losses, lambda_draws, success_chain_draws, out_dir){
  ts <- format(Sys.time(), "%Y-%m-%d_%H-%M-%S")
  succ_per_year <- lambda_draws * success_chain_draws

  auto_clip <- function(x, low=0.001, high=0.991){
    qs <- quantile(x, probs=c(low,high), na.rm=TRUE)
    x[x >= qs[1] & x <= qs[2]]
  }
  lp <- auto_clip(lambda_draws)
  sp <- auto_clip(success_chain_draws)
  sy <- auto_clip(succ_per_year)
  ls <- auto_clip(losses)

  p1 <- ggplot(data.frame(x=lp), aes(x=x)) +
        geom_histogram(bins=60, color="black") +
        labs(title="Posterior λ (incidents/year)", x="λ", y="Count")
  p1 <- add_percentile_lines(p1, lp)

  p2 <- ggplot(data.frame(x=sp), aes(x=x)) +
        geom_histogram(bins=60, color="black") +
        labs(title="Posterior Success Probability (end-to-end)", x="Success prob", y="Count")
  p2 <- add_percentile_lines(p2, sp)

  p3 <- ggplot(data.frame(x=sy), aes(x=x)) +
        geom_histogram(bins=60, color="black") +
        labs(title="Successful Incidents / Year (posterior)", x="Incidents/year", y="Count")
  p3 <- add_percentile_lines(p3, sy)

  p4 <- ggplot(data.frame(x=ls), aes(x=x)) +
        geom_histogram(bins=60, color="black") +
        scale_x_continuous(labels=function(v) if (PLOT_IN_MILLIONS) paste0("$", format(v/1e6, big.mark=",", scientific=FALSE), "M") else scales::dollar(v)) +
        labs(title="Annual Loss (posterior predictive)", x="Annual loss", y="Count")
  p4 <- add_percentile_lines(p4, ls)

  # LEC on log scale — avoid log(0) by clipping to >= 1
  ord <- sort(pmax(ls, 1))
  exceed <- 1 - (seq_along(ord) / length(ord))
  lec <- ggplot(data.frame(loss=ord, p=exceed*100), aes(x=loss, y=p)) +
         geom_line() +
         scale_x_log10(labels=function(v) if (PLOT_IN_MILLIONS) paste0("$", format(v/1e6, big.mark=",", scientific=FALSE), "M") else scales::dollar(v)) +
         labs(title="Loss Exceedance Curve (Annual Loss)", x="Annual Loss", y="Exceedance Probability (%)")

  ggsave(filename = file.path(out_dir, paste0("dashboard_lambda_", ts, ".png")), plot = p1, width=7, height=5, dpi=150)
  ggsave(filename = file.path(out_dir, paste0("dashboard_success_chain_", ts, ".png")), plot = p2, width=7, height=5, dpi=150)
  ggsave(filename = file.path(out_dir, paste0("dashboard_incidents_year_", ts, ".png")), plot = p3, width=7, height=5, dpi=150)
  ggsave(filename = file.path(out_dir, paste0("loss_exceedance_curve_", ts, ".png")), plot = lec, width=7, height=5, dpi=150)
  ggsave(filename = file.path(out_dir, paste0("dashboard_annual_loss_", ts, ".png")), plot = p4, width=7, height=5, dpi=150)
}

# ----------------------------------------------------------------------------
# CSV outputs
# ----------------------------------------------------------------------------
save_results <- function(losses, successes, lambda_draws, success_chain_draws, out_dir, summary_only=FALSE){
  ts <- format(Sys.time(), "%Y-%m-%d_%H-%M-%S")
  if (!isTRUE(summary_only)) {
    res_path <- file.path(out_dir, paste0("cyber_risk_simulation_results_", ts, ".csv"))
    readr::write_csv(data.frame(
      lambda=lambda_draws,
      p_success_chain=success_chain_draws,
      annual_loss=losses,
      successful_incidents=successes
    ), res_path)
    message("✅ Detailed results → ", res_path)
  }
  aal_mean <- mean(losses); aal_median <- median(losses); ci <- quantile(losses, c(0.025, 0.975))
  mean_succ <- mean(successes); succ_ci <- quantile(successes, c(0.025, 0.975)); pct_zero <- mean(successes == 0) * 100

  valid <- successes > 0
  if (any(valid)) {
    per_event <- losses[valid] / pmax(1, successes[valid])
    mean_loss_per_event <- mean(per_event); leci <- quantile(per_event, c(0.025, 0.975))
  } else {
    mean_loss_per_event <- 0; leci <- c(0,0)
  }

  sum_path <- file.path(out_dir, paste0("cyber_risk_simulation_summary_", ts, ".csv"))
  readr::write_csv(data.frame(
    Mean_AAL = aal_mean, Median_AAL = aal_median,
    AAL_95_Lower = ci[1], AAL_95_Upper = ci[2],
    Mean_Incidents = mean_succ, Zero_Incident_Years_ = pct_zero, n = length(losses),
    Incidents_95_Lower = succ_ci[1], Incidents_95_Upper = succ_ci[2],
    Mean_Loss_Per_Incident = mean_loss_per_event,
    Loss_Per_Incident_95_Lower = leci[1], Loss_Per_Incident_95_Upper = leci[2],
    Mean_AAL_Check_MeanInc_x_MeanLossPerIncident = mean_succ * mean_loss_per_event
  ), sum_path)
  message("✅ Summary stats → ", sum_path)
}

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
main <- function(){
  option_list <- list(
    make_option(c("-d","--dataset"), type="character", default="enterprise-attack.json", help="MITRE dataset path [default %default]"),
    make_option(c("-s","--strengths"), type="character", default="mitigation_control_strengths.csv", help="Mitigation strengths CSV [default %default]"),
    make_option(c("-n","--samples"), type="integer", default=4000, help="Posterior draws per chain [default %default]"),
    make_option(c("-c","--chains"), type="integer", default=4, help="MCMC chains [default %default]"),
    make_option(c("-t","--tune"), type="integer", default=1000, help="Warmup iterations [default %default]"),
    make_option(c("-S","--seed"), type="integer", default=42, help="Random seed [default %default]"),
    make_option(c("-N","--no-plot"), action="store_true", default=FALSE, help="Skip ggplot outputs"),
    make_option(c("-y","--summary-only"), action="store_true", default=FALSE, help="Write only summary CSV (skip per-draw CSV)"),
    make_option(c("-o","--output-dir"), type="character", default=NULL, help="Override output directory"),
    make_option(c("-q","--quiet"), action="store_true", default=FALSE, help="Suppress console messages")
  )
  opt <- parse_args(OptionParser(option_list = option_list))

  out_dir <- make_output_dir(override = opt$`output-dir`, quiet = opt$quiet)
  if (!opt$quiet) {
    cat("───────────────────────────────────────────────\n")
    cat("FAIR–MITRE RISK MODEL (cmdstanr)\n")
    cat("Dataset:", opt$dataset, "\n")
    cat("Strengths:", opt$strengths, "\n")
    cat("Samples:", opt$samples, " | Chains:", opt$chains, " | Tune:", opt$tune, " | Seed:", opt$seed, "\n")
    cat("Summary only:", isTRUE(opt$`summary-only`), " | Plotting:", !isTRUE(opt$`no-plot`), "\n")
    cat("Output dir:", out_dir, "\n")
  }

  strengths <- get_strengths(dataset = opt$dataset, csv = opt$strengths,
                             outdir = out_dir, quiet = opt$quiet, relevance_file = "technique_relevance.csv")
  tactics <- strengths$tactics; K <- length(tactics)
  if (!opt$quiet) cat("Included tactics (", strengths$mode, "): ", K, " / 12\n", sep = "")
  if (K == 0) stop("No tactics included. Check technique_relevance.csv.", call.=FALSE)

  pri <- build_beta_priors(strengths$stage_map, tactics)

  mu_lambda <- log(sqrt(CI_MIN_FREQ * CI_MAX_FREQ))
  sigma_lambda <- (log(CI_MAX_FREQ) - log(CI_MIN_FREQ)) / (2.0 * 1.645)

  data_list <- list(
    K = K,
    alpha = as.vector(pri$alpha),
    beta  = as.vector(pri$beta),
    mu_lambda = mu_lambda,
    sigma_lambda = sigma_lambda
  )
  
  # ----------------------------------------------------------------------------
  # Stan model compilation (force rebuild every run)
  # ----------------------------------------------------------------------------
  stan_path <- write_stan_file(
    stan_code,
    dir = tempdir(),
    basename = "fair_mitre_model.stan"
  )
  mod <- cmdstan_model(stan_path, force_recompile = TRUE)
  
  # Quick sanity check: confirm parameters visible to CmdStan
  cat("Detected Stan parameters:\n")
  print(mod$variables()$parameters)
  
  # ----------------------------------------------------------------------------
  # Sampling
  # ----------------------------------------------------------------------------
  fit <- mod$sample(
    data = data_list,
    seed = opt$seed,
    chains = opt$chains,
    iter_warmup = opt$tune,
    iter_sampling = opt$samples,
    refresh = 200,
    parallel_chains = min(opt$chains, max(1, parallel::detectCores()-1))
  )
  
  # ---- Extract posterior draws safely (stack chains row-wise) ----
  draws <- as.data.frame(fit$draws())
  
  # =========================================================
  # === Diagnostic Block 1: Posterior draw diagnostics ======
  # =========================================================
  cat("\n--- POSTERIOR DRAWS DIAGNOSTIC ---\n")
  cat("Number of draws:", nrow(draws), "\n")
  cat("Column sample (first 10):", paste(head(names(draws), 10), collapse=", "), "\n")
  
  # mean of lambda_rate across all chains
  lambda_cols <- grep("lambda_rate", names(draws), value = TRUE)
  tmp_lambda <- unlist(draws[, lambda_cols, drop = FALSE], use.names = FALSE)
  cat("λ mean (across all chains):", mean(tmp_lambda), "\n")
  
  # mean success_prob per draw, once we build succ_mat later
  # (we'll print this again after succ_mat is defined)
  # =========================================================
  
  # Determine number of chains from prefixes like "1."
  chain_ids <- sort(unique(sub("\\..*$", "", grep("^\\d+\\.", names(draws), value = TRUE))))
  if (length(chain_ids) == 0) chain_ids <- "1"
  
  # ----- Lambda draws -----
  lambda_cols <- grep("lambda_rate", names(draws), value = TRUE)
  lambda_list <- lapply(chain_ids, function(ch) draws[[paste0(ch, ".lambda_rate")]])
  lambda_draws <- unlist(lambda_list, use.names = FALSE)
  
  # ----- Success-prob draws -----
  # detect how many per chain
  first_chain_succ <- grep(paste0("^", chain_ids[1], "\\.success_probs\\[\\d+\\]$"),
                           names(draws), value = TRUE)
  K_detected <- length(first_chain_succ)
  if (K_detected == 0)
    stop("No success_probs columns found in posterior draws.")
  
  succ_list <- lapply(chain_ids, function(ch) {
    sc <- grep(paste0("^", ch, "\\.success_probs\\[\\d+\\]$"),
               names(draws), value = TRUE)
    sc_idx <- as.integer(sub(".*\\[(\\d+)\\]$", "\\1", sc))
    sc <- sc[order(sc_idx)]
    as.matrix(draws[, sc, drop = FALSE])
  })
  
  succ_mat <- do.call(rbind, succ_list)
  
  if (nrow(succ_mat) != length(lambda_draws))
    stop("Row mismatch: succ_mat=", nrow(succ_mat), " lambda_draws=", length(lambda_draws))
  
  success_chain_draws <- if (ncol(succ_mat) == 1) succ_mat[, 1] else apply(succ_mat, 1, prod)
  
  cat("Mean of chain success probabilities:", mean(success_chain_draws), "\n")
  
  cat("Extracted", length(lambda_draws), "lambda draws and",
      ncol(succ_mat), "success_prob columns (", length(chain_ids),
      "chains, ", K_detected, " tactics each).\n")
  
  # -----------------------------------------------------------------------------------------
  
  sim <- simulate_posterior_predictive(lambda_draws, succ_mat, tactics, strengths$impact_controls)
  losses <- sim$losses; successes <- sim$successes

  if (!opt$quiet) {
    aal_mean <- mean(losses); aal_median <- median(losses); ci <- quantile(losses, c(0.025, 0.975))
    mean_succ <- mean(successes); succ_ci <- quantile(successes, c(0.025, 0.975)); pct_zero <- mean(successes == 0) * 100
    cat("───────────────────────────────────────────────\n")
    cat("AAL posterior predictive summary:\n")
    cat("Mean AAL:", fmt_money(aal_mean), "\n")
    cat("Median AAL:", fmt_money(aal_median), "\n")
    cat("AAL 95% CI:", fmt_money(ci[1]), "–", fmt_money(ci[2]), "\n")
    cat("Mean successful incidents / year:", sprintf("%.2f", mean_succ), "\n")
    cat("95% CI (incidents / year):", sprintf("%.2f – %.2f", succ_ci[1], succ_ci[2]), "\n")
    cat("% years with zero successful incidents:", sprintf("%.1f%%", pct_zero), "\n")
    cat("───────────────────────────────────────────────\n")
  }

  save_results(losses, successes, lambda_draws, success_chain_draws, out_dir, summary_only = isTRUE(opt$`summary-only`))
  if (!isTRUE(opt$`no-plot`)) render_plots(losses, lambda_draws, success_chain_draws, out_dir)
}

if (identical(environment(), globalenv())) main()
