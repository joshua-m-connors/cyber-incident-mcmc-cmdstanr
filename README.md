# FAIR–MITRE ATT&CK Quantitative Risk Model (R / cmdstanr)

This repository implements a **FAIR-aligned, MITRE ATT&CK–informed quantitative cyber risk model** using Bayesian inference and Monte Carlo simulation. The primary goal is to estimate **annualized loss distributions** while preserving uncertainty, attacker behavior, and control effectiveness in a way that supports **decision-making and scenario comparison**, not point prediction.

The core execution path is implemented in **R using cmdstanr**, with supporting scripts for building control strength inputs, technique relevance mappings, and dashboards.

---

## 1. Conceptual Overview

### What this model does

At a high level, the model:

1. Represents **attack attempts per year** as an uncertain frequency distribution
2. Simulates attacker progression through a **MITRE ATT&CK tactic chain**
3. Applies **control strength and threat capability** to determine stage success
4. Models **detection and retry behavior** explicitly
5. Simulates **financial loss** for successful incidents using bounded severity distributions
6. Produces **annualized loss distributions (AAL, percentiles, exceedance curves)**

All outputs are **distributions**, not single values.

### What this model is not

- It is **not** a deterministic forecast
- It is **not** a risk scoring system
- It does **not** assume repeated attempts guarantee success

---

## 2. Core Modeling Principles

### FAIR alignment

The model follows FAIR principles:

- Frequency and magnitude are modeled separately
- Loss is expressed in **financial terms**
- Uncertainty is preserved throughout the analysis

### MITRE ATT&CK integration

MITRE ATT&CK provides:

- The **attack progression structure** (tactics)
- Technique-level mappings for controls and relevance

Controls are mapped to techniques, then aggregated to tactic-level effectiveness ranges.

---

## 3. Detection and Adaptability (Important)

The R implementation uses **strict, bounded logic**:

- **Adaptability does NOT increase success probability**
- Adaptability **only governs persistence** (whether retries are allowed after failure)
- Retries are capped by `MAX_RETRIES_PER_STAGE`
- **Detection probability increases with repeated attempts**

This prevents the common modeling error where retries converge to certainty.

---

## 4. Bayesian Structure

### Why Bayesian inference

Cyber risk is under-observed. We rarely have complete, clean data.

Bayesian inference allows us to:

- Encode uncertainty as distributions
- Combine priors with limited evidence
- Produce posterior distributions that support comparison

### Posterior interpretation

Each posterior draw represents **one internally consistent version of reality**, including:

- Annual attempt rate
n- Per-tactic success probabilities
- Loss severity behavior

Posterior predictive simulation explores a **space of plausible outcomes**, not a single future.

---

## 5. Observed Data Conditioning (Optional)

The model can optionally be conditioned on **observed breach counts**.

- Conditioning applies **only to frequency**
- Implemented as a Poisson likelihood on observed incidents over observed years
- Per-tactic success probabilities remain uncertain unless stage-level data exists

If no observed data is provided, the model runs fully prior-driven.

---

## 6. Repository Structure

```
.
├── cyber_incident_cmdstanr.R              # Main model runner (cmdstanr)
├── build_mitigation_influence_template.R # Builds mitigation→technique influence matrix
├── build_technique_relevance_template.R  # Builds technique relevance weights
├── mitre_control_strength_dashboard.R    # Visualization and diagnostics dashboard
├── mitigation_control_strengths.csv
├── technique_relevance.csv
├── mitigation_influence_template.csv
├── README.md
```

---

## 7. Prerequisites

### System requirements

- R >= 4.2
- CmdStan >= 2.33

### R packages

```r
install.packages(c(
  "cmdstanr",
  "posterior",
  "ggplot2",
  "dplyr",
  "tidyr",
  "optparse",
  "jsonlite"
))
```

Install CmdStan (once):

```r
cmdstanr::install_cmdstan()
```

### Provide MITRE ATT&CK Dataset

Download MITRE ATT&CK Enterprise JSON:

```bash
wget https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```
---

## 8. Supporting Scripts (How and When to Use Them)

### 8.1 `build_mitigation_influence_template.R`

**Purpose**  
Generates a template CSV that defines how individual MITRE ATT&CK mitigations influence specific techniques.

**When to use it**
- When initializing the model for a new environment
- When adding new mitigations
- When refining SME judgments about control impact

**What it produces**
- `mitigation_influence_template.csv`

This file assigns **relative influence weights** that are later used to roll mitigation strength up from technique to tactic.

**How to run**
```bash
Rscript build_mitigation_influence_template.R
```

You are expected to review and edit the generated CSV before running the main model.

---

### 8.2 `build_technique_relevance_template.R`

**Purpose**  
Builds a template for weighting how relevant each ATT&CK technique is to the modeled threat context.

**When to use it**
- To scope the model to specific threat actors
- To reflect industry or environment-specific attack patterns
- To incorporate threat intelligence into the model

**What it produces**
- `technique_relevance.csv`

Higher weights indicate techniques that are more likely or more important in the modeled scenario.

**How to run**
```bash
Rscript build_technique_relevance_template.R
```

---

### 8.3 `mitre_control_strength_dashboard.R`

**Purpose**  
Provides a visual and diagnostic view of how control strengths and relevance weights aggregate from techniques to tactics.

**When to use it**
- To validate that inputs behave as expected
- To debug unexpected model results
- To support analyst review and stakeholder explanation

**What it consumes**
- `mitigation_control_strengths.csv`
- `mitigation_influence_template.csv`
- `technique_relevance.csv`

**How to run**
```bash
Rscript mitre_control_strength_dashboard.R
```

The dashboard helps ensure that tactic-level effectiveness ranges are reasonable before running simulations.

---

## 9. Input Files

### `mitigation_control_strengths.csv`

Defines **min/max control effectiveness** per mitigation.

- Values are on [0, 1]
- Higher means stronger controls

### `technique_relevance.csv`

Weights how relevant each technique is for the modeled threat context.

Used to roll technique controls up to tactics.

---

## 10. Running the Model

Basic run:

```bash
Rscript cyber_incident_cmdstanr.R \
  --dataset enterprise-attack.json \
  --strengths mitigation_control_strengths.csv \
  --technique-relevance technique_relevance.csv
```

With observed data conditioning:

```bash
Rscript cyber_incident_cmdstanr.R \
  --observed-incidents 2 \
  --observed-years 5
```

Key CLI options:

- `--samples` Number of posterior samples
- `--chains` Number of MCMC chains
- `--seed` Random seed
- `--summary-only` Skip plots

---

## 10. Outputs

The model produces:

- Annualized loss distributions
- Mean and median AAL
- Percentiles and credible intervals
- Probability of zero-loss years
- Exceedance curves

Outputs are written to a timestamped directory.

---

## 11. Interpreting Results

Focus on:

- **Comparison**, not precision
- Changes in percentiles and exceedance probabilities
- Directional sensitivity to control improvements

The most defensible statements are comparative:

> "Improving detection reduces the probability of exceeding $10M annual loss from X% to Y%."

---

## 12. Limitations and Use Guidance

- Results depend on assumptions
- Best used for **scenario comparison**
- Do not over-interpret single point estimates

This model is designed to support **structured reasoning under uncertainty**, not prediction certainty.

---

## 13. License and Disclaimer

This project is provided for research and decision-support purposes. It is not a guarantee of security outcomes.

