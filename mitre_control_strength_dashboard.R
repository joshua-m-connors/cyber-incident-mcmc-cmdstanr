#!/usr/bin/env Rscript
# MITRE ATT&CK Control Strength Dashboard (R)
# Version: v1.1.2
# -----------------------------------------------------------------------------
# WHAT THIS DOES
#   • Loads the MITRE ATT&CK STIX dataset (enterprise-attack.json).
#   • Optionally filters techniques/tactics using a user-maintained
#     technique_relevance.csv (rows marked in scope are included).
#   • Aggregates mitigation control strengths BY TACTIC using
#     mitigation_control_strengths.csv, respecting influence weights and
#     de-duplicating repeated mitigations.
#   • Writes a CSV summary and (optionally) an interactive Plotly chart.
#   • Returns a compact structure for the risk model to consume:
#       - included_tactics (vector of tactic names, in ATT&CK order)
#       - stage_map (tactic -> list(min_strength, max_strength, mean_strength, mitigation_count))
#       - impact_controls (Data Backup, Encrypt Sensitive Information) with gating logic
#
# KEY FIXES IN v1.1.2
#   • Robust relevance CSV parsing (flexible headers; tolerant marks; Title-Case tactics; uppercased technique IDs).
#   • Diagnostics: counts matched/unmatched technique IDs against STIX.
#   • Safe fallback: if filter yields zero tactics, fall back to FULL mode automatically.
#   • Preserves your hover-over formatting and dashboard visuals.
#
# HOW THIS FILE IS USED
#   • You can run this script directly from the CLI to produce a dashboard & CSV.
#   • The risk model script `cyber_incident_cmdstanr.R` also sources this file to
#     obtain a consistent, filtered set of tactic strengths.
# -----------------------------------------------------------------------------

suppressPackageStartupMessages({
  library(jsonlite)
  library(dplyr)
  library(readr)
  library(stringr)
  library(tidyr)
  library(plotly)
  library(htmlwidgets)
  library(optparse)
})

`%||%` <- function(a,b){ if (is.null(a)) b else a }

# Controls that get discounted weight (kept aligned with Python version)
DISCOUNT_CONTROLS <- c(
  "audit","vulnerability scanning","user training",
  "threat intelligence program","application developer guidance"
)

# Limit hover items to keep tooltips readable
MAX_HOVER_ITEMS <- 20

# ============================================================================
# I/O HELPERS
# ============================================================================
make_output_dir <- function(prefix="output", override=NULL, quiet=FALSE){
  out_dir <- override
  if (is.null(out_dir) || !nzchar(out_dir)) {
    out_dir <- file.path(getwd(), paste0(prefix, "_", format(Sys.Date(), "%Y-%m-%d")))
  }
  if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
  if (!quiet) message("📁 Output directory: ", out_dir)
  out_dir
}

# ============================================================================
# STIX HELPERS
# ============================================================================
load_stix <- function(path){
  dat <- fromJSON(path, simplifyVector = FALSE)
  objs <- if (!is.null(dat$objects)) dat$objects else dat
  techniques    <- Filter(function(o) o$type == "attack-pattern", objs)
  mitigations   <- Filter(function(o) o$type == "course-of-action", objs)
  relationships <- Filter(function(o) o$type == "relationship" && o$relationship_type == "mitigates", objs)
  list(techniques=techniques, mitigations=mitigations, relationships=relationships)
}

# Build a tactic -> mitigation-id map for the full dataset
build_tactic_map_full <- function(techniques, mitigations, relationships){
  tactic_map <- list()
  for (rel in relationships) {
    src <- rel$source_ref; tgt <- rel$target_ref
    if (!startsWith(src, "course-of-action") || !startsWith(tgt, "attack-pattern")) next
    tech <- Filter(function(t) t$id == tgt, techniques)
    if (length(tech) == 0) next
    for (ref in tech[[1]]$kill_chain_phases %||% list()) {
      tactic <- stringr::str_to_title(stringr::str_replace_all(ref$phase_name %||% "", "-", " "))
      if (nzchar(tactic)) tactic_map[[tactic]] <- c(tactic_map[[tactic]] %||% character(), src)
    }
  }
  Filter(length, tactic_map)
}

# ============================================================================
# RELEVANCE CSV LOADER (ROBUST)
#   Accepts headers: Tactic, TechniqueID / Technique / Technique_ID
#   Accepts marks:  X, TRUE, T, 1, YES, Y (case-insensitive)
#   Tactics normalized to Title Case; technique IDs uppercased.
# ============================================================================
load_relevance_filter <- function(path){
  df <- readr::read_csv(path, show_col_types = FALSE)
  norm <- setNames(tolower(gsub("[ _]", "", names(df))), names(df))

  tactic_col <- names(norm)[norm == "tactic"][1]
  tech_col   <- names(norm)[norm %in% c("techniqueid","technique","technique_id")][1]
  mark_col   <- names(norm)[norm %in% c("relevant","include","selected","in_scope","inscope")][1]

  if (is.na(tactic_col) || is.na(tech_col) || is.na(mark_col)) {
    stop("technique_relevance.csv missing required columns (need: Tactic, TechniqueID/Technique, Relevant/Include).")
  }

  marks <- toupper(trimws(as.character(df[[mark_col]])))
  mask  <- marks %in% c("X","TRUE","T","1","YES","Y")

  kept <- df[mask, c(tactic_col, tech_col)]
  kept[[tactic_col]] <- kept[[tactic_col]] |> as.character() |> trimws()
  kept[[tactic_col]] <- stringr::str_to_title(stringr::str_replace_all(kept[[tactic_col]], "-", " "))
  kept[[tech_col]]   <- kept[[tech_col]]   |> as.character() |> toupper() |> trimws()

  kept <- kept[nchar(kept[[tactic_col]]) > 0 & nchar(kept[[tech_col]]) > 0, , drop=FALSE]

  list(
    tech_ids    = unique(kept[[tech_col]]),
    tactics_keep= unique(kept[[tactic_col]])
  )
}

# Build a tactic map but keep only techniques explicitly marked in the CSV
build_tactic_map_filtered <- function(techniques, mitigations, relationships, tech_ids_keep, tactics_keep){
  tactic_map <- list()
  ap_ext <- new.env(parent=emptyenv())  # attack-pattern ID -> external_id (e.g., T1059)
  for (t in techniques) {
    ext <- NA_character_
    for (r in t$external_references %||% list()) {
      if (r$source_name == "mitre-attack") { ext <- toupper(r$external_id); break }
    }
    ap_ext[[t$id]] <- ext
  }
  for (rel in relationships) {
    src <- rel$source_ref; tgt <- rel$target_ref
    if (!startsWith(src, "course-of-action") || !startsWith(tgt, "attack-pattern")) next
    ext_tid <- ap_ext[[tgt]]
    if (is.na(ext_tid) || !(ext_tid %in% tech_ids_keep)) next
    tech <- Filter(function(t) t$id == tgt, techniques)
    if (length(tech) == 0) next
    for (ref in tech[[1]]$kill_chain_phases %||% list()) {
      tactic <- stringr::str_to_title(stringr::str_replace_all(ref$phase_name %||% "", "-", " "))
      if (nzchar(tactic) && tactic %in% tactics_keep) {
        tactic_map[[tactic]] <- c(tactic_map[[tactic]] %||% character(), src)
      }
    }
  }
  Filter(length, tactic_map)
}

# ============================================================================
# STRENGTH AGGREGATION
#   - Merges duplicate mitigation names (weighted).
#   - Applies discounted influence to "soft" controls (audit/training/etc.).
# ============================================================================
compute_tactic_strengths <- function(tactic_map, mitigations, strengths_map, discount_controls = DISCOUNT_CONTROLS){
  # Map mitigation STIX ID -> external_id (e.g., M1030), used as CSV key fallback.
  mit_id_to_ext <- new.env(parent=emptyenv())
  for (m in mitigations) {
    ext <- NA_character_
    for (r in m$external_references %||% list())
      if (r$source_name == "mitre-attack") { ext <- tolower(r$external_id); break }
    mit_id_to_ext[[tolower(m$id)]] <- ext
  }

  detail_rows <- list(); summary_rows <- list()
  idx <- 1; jdx <- 1
  for (tac in names(tactic_map)) {
    mit_ids <- tactic_map[[tac]]
    entries <- list()
    for (mid in mit_ids) {
      mobj <- Filter(function(m) m$id == mid, mitigations)[[1]]
      name <- mobj$name %||% "Unknown Mitigation"
      name_lower <- tolower(name)
      ext_id <- mit_id_to_ext[[tolower(mid)]]
      strength <- strengths_map[[tolower(mid)]]
      if (is.null(strength) && !is.na(ext_id)) strength <- strengths_map[[ext_id]]
      lo <- ifelse(is.null(strength), 30.0, strength[1])   # default min
      hi <- ifelse(is.null(strength), 70.0, strength[2])   # default max
      # Influence weight: some mitigations (training/audit/etc.) down-weighted
      w  <- if (grepl("do not mitigate", name_lower, fixed=TRUE)) 1.0
            else if (any(stringr::str_detect(name_lower, discount_controls))) 0.5
            else 1.0
      entries <- append(entries, list(list(name=name, lo=lo, hi=hi, w=w)))
    }

    # Combine duplicate names by influence-weighted average
    agg <- list()
    for (e in entries) {
      key <- e$name
      if (is.null(agg[[key]])) agg[[key]] <- list(sum_lo=0, sum_hi=0, sum_w=0)
      agg[[key]]$sum_lo <- agg[[key]]$sum_lo + e$lo * e$w
      agg[[key]]$sum_hi <- agg[[key]]$sum_hi + e$hi * e$w
      agg[[key]]$sum_w  <- agg[[key]]$sum_w  + e$w
    }
    weighted <- do.call(rbind, lapply(names(agg), function(nm){
      sw <- agg[[nm]]$sum_w
      data.frame(
        lo = agg[[nm]]$sum_lo / max(1e-9, sw),
        hi = agg[[nm]]$sum_hi / max(1e-9, sw),
        name = nm, w = sw, stringsAsFactors = FALSE
      )
    }))
    total_w <- sum(weighted$w); if (total_w <= 0) total_w <- 1e-9
    avg_min <- sum(weighted$lo * weighted$w) / total_w
    avg_max <- sum(weighted$hi * weighted$w) / total_w
    items_sorted <- weighted[order(-weighted$w), ]

    lines <- paste0(
      items_sorted$name, ": ",
      sprintf('%.1f', items_sorted$lo), "–", sprintf('%.1f', items_sorted$hi),
      "% (influence ", sprintf('%.1f', (items_sorted$w/total_w)*100.0), "%)"
    )

    detail_rows[[idx]] <- data.frame(
      Tactic=tac, MinStrength=avg_min, MaxStrength=avg_max,
      MitigationLines = I(list(lines)), stringsAsFactors = FALSE
    )
    summary_rows[[jdx]] <- data.frame(
      Tactic=tac, MinStrength=avg_min, MaxStrength=avg_max,
      MitigationCount=nrow(items_sorted), stringsAsFactors = FALSE
    )
    idx <- idx + 1; jdx <- jdx + 1
  }

  detail_df <- dplyr::bind_rows(detail_rows); summary_df <- dplyr::bind_rows(summary_rows)

  # ATT&CK order for readability
  order <- c("Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
             "Credential Access","Discovery","Lateral Movement","Collection","Command And Control",
             "Exfiltration","Impact")
  detail_df$Tactic <- factor(detail_df$Tactic, levels=order, ordered=TRUE)
  summary_df$Tactic <- factor(summary_df$Tactic, levels=order, ordered=TRUE)
  detail_df <- detail_df %>% arrange(Tactic) %>% tidyr::drop_na(Tactic)
  summary_df <- summary_df %>% arrange(Tactic) %>% tidyr::drop_na(Tactic)

  list(detail=detail_df, summary=summary_df)
}

# ============================================================================
# CORE CALLABLE (used by model + CLI)
# ============================================================================
get_mitre_tactic_strengths <- function(dataset_path="enterprise-attack.json", csv_path="mitigation_control_strengths.csv",
                                       use_relevance=FALSE, relevance_file="technique_relevance.csv",
                                       build_figure=TRUE, output_dir=NULL, quiet=FALSE, show_figure=FALSE){
  ts <- format(Sys.time(), "%Y-%m-%d_%H-%M-%S")
  out_dir <- make_output_dir(override = output_dir, quiet = quiet)
  stix <- load_stix(dataset_path)

  # --- Build map (filtered or full), with diagnostics & safe fallback --------
  mode_label <- "Full"
  tactic_map <- NULL

  if (use_relevance && file.exists(relevance_file)) {
    flt <- tryCatch(load_relevance_filter(relevance_file), error=function(e) { if (!quiet) message("Filter load error: ", e$message); NULL })
    if (!is.null(flt)) {
      # Diagnostics: how many tech IDs match STIX?
      ap_ext <- toupper(unlist(lapply(stix$techniques, function(t){
        ext <- NA_character_
        for (r in t$external_references %||% list()) if (r$source_name=="mitre-attack") { ext <- r$external_id; break }
        ext
      })))
      matched   <- intersect(flt$tech_ids, ap_ext)
      unmatched <- setdiff(flt$tech_ids, ap_ext)
      if (!quiet) {
        message("🔎 Relevance CSV: kept techniques=", length(flt$tech_ids), " | kept tactics=", length(flt$tactics_keep))
        message("   Matched to STIX attack-patterns: ", length(matched), " | Unmatched: ", length(unmatched))
        if (length(unmatched) > 0) message("   (Example unmatched): ", paste(utils::head(unmatched, 6), collapse=", "))
      }

      tactic_map <- build_tactic_map_filtered(stix$techniques, stix$mitigations, stix$relationships,
                                              flt$tech_ids, flt$tactics_keep)

      if (length(tactic_map) > 0) {
        mode_label <- "Filtered"
      } else {
        if (!quiet) message("⚠️ Filtered set produced zero tactics — falling back to FULL mode.")
        tactic_map <- build_tactic_map_full(stix$techniques, stix$mitigations, stix$relationships)
        mode_label <- "Filtered (fallback→Full)"
      }
    } else {
      tactic_map <- build_tactic_map_full(stix$techniques, stix$mitigations, stix$relationships)
      if (!quiet) message("⚙️ FULL mode (filter load error).")
    }
  } else {
    tactic_map <- build_tactic_map_full(stix$techniques, stix$mitigations, stix$relationships)
    if (!quiet) message("⚙️ FULL mode (no filtering).")
  }

  # --- Load strengths CSV into a lookup (Mitigation_ID tolerant) --------------
  csv <- tryCatch(readr::read_csv(csv_path, show_col_types = FALSE), error=function(e) NULL)
  csv_map <- new.env(parent=emptyenv())
  if (!is.null(csv)) {
    cn <- tolower(names(csv))
    id_col  <- names(csv)[match("mitigation_id", cn)]
    min_col <- names(csv)[match("control_min", cn)]
    max_col <- names(csv)[match("control_max", cn)]
    if (is.na(id_col) || is.na(min_col) || is.na(max_col)) {
      stop("mitigation_control_strengths.csv must have columns: Mitigation_ID, Control_Min, Control_Max")
    }
    csv[[id_col]] <- tolower(trimws(as.character(csv[[id_col]])))
    for (i in seq_len(nrow(csv))) {
      csv_map[[csv[[id_col]][i]]] <- c(as.numeric(csv[[min_col]][i]), as.numeric(csv[[max_col]][i]))
    }
    if (!quiet) message("✅ Loaded ", nrow(csv), " mitigation strengths.")
  } else if (!quiet) {
    message("⚠️ Could not load strengths; defaulting to 30–70%.")
  }

  # --- Aggregate strengths ----------------------------------------------------
  res <- compute_tactic_strengths(tactic_map, stix$mitigations, csv_map)

  # --- Impact controls (for impact reduction gating in the risk model) --------
  impact_controls <- new.env(parent=emptyenv())
  for (m in stix$mitigations) {
    nm <- m$name %||% ""
    lower <- tolower(nm)
    if (grepl("data backup", lower) || grepl("encrypt sensitive information", lower)) {
      ext <- NA_character_
      for (r in m$external_references %||% list())
        if (r$source_name == "mitre-attack") { ext <- tolower(r$external_id); break }
      strv <- csv_map[[ext]]
      lo <- ifelse(is.null(strv), 30.0, strv[1]); hi <- ifelse(is.null(strv), 70.0, strv[2])
      impact_controls[[nm]] <- c(min_strength=lo, max_strength=hi, mean_strength=(lo+hi)/2)
    }
  }
  # Gating rules:
  # - Encryption disabled unless Exfiltration tactic included
  if (!("Exfiltration" %in% res$summary$Tactic) && !is.null(impact_controls[["Encrypt Sensitive Information"]])) {
    impact_controls[["Encrypt Sensitive Information"]] <- c(min_strength=0, max_strength=0, mean_strength=0)
  }
  # - Backup disabled unless there exists a Backup mapping in Impact
  has_backup_in_impact <- FALSE
  try({
    imp_row <- res$detail %>% dplyr::filter(Tactic == "Impact")
    if (nrow(imp_row)) {
      lines <- imp_row$MitigationLines[[1]]
      has_backup_in_impact <- any(grepl("data backup", tolower(lines)))
    }
  }, silent=TRUE)
  if (!has_backup_in_impact && !is.null(impact_controls[["Data Backup"]])) {
    impact_controls[["Data Backup"]] <- c(min_strength=0, max_strength=0, mean_strength=0)
  }

  # --- Optional interactive figure -------------------------------------------
  if (build_figure && nrow(res$detail)) {
    det <- res$detail
    bullets <- lapply(seq_len(nrow(det)), function(i){
      lines <- det$MitigationLines[[i]]
      extra <- ""
      if (length(lines) > MAX_HOVER_ITEMS) {
        extra_count <- length(lines) - MAX_HOVER_ITEMS
        lines <- lines[seq_len(MAX_HOVER_ITEMS)]
        extra <- paste0("<br>… and ", extra_count, " more")
      }
      paste0("Tactic: ", det$Tactic[i],
             "<br>Min Strength: ", sprintf("%.1f", det$MinStrength[i]), "%",
             "<br>Max Strength: ", sprintf("%.1f", det$MaxStrength[i]), "%",
             "<br><br>Mitigations:<br>",
             paste0("• ", lines, collapse="<br>"),
             extra)
    })
    fig <- plot_ly()
    fig <- fig %>% add_bars(x=det$Tactic, y=det$MinStrength, name="Min Strength (%)", marker=list(color="skyblue"), hoverinfo="skip")
    fig <- fig %>% add_bars(x=det$Tactic, y=det$MaxStrength, name="Max Strength (%)", marker=list(color="steelblue"), hovertemplate = unlist(bullets))
    fig <- fig %>% layout(barmode="group",
                          title=paste0("Weighted MITRE ATT&CK Control Strengths by Tactic (", mode_label, ")"),
                          xaxis=list(title="Tactic"), yaxis=list(title="Control Strength (%)"),
                          hovermode="x unified")
    html_path <- file.path(out_dir, paste0("mitre_tactic_strengths_", ts, ".html"))
    htmlwidgets::saveWidget(as_widget(fig), file = html_path, selfcontained = TRUE)
    if (!quiet) message("✅ Chart saved → ", html_path)
    if (isTRUE(show_figure)) { try(browseURL(html_path), silent = TRUE) }
  }

  # --- Write CSV summary ------------------------------------------------------
  summary_out <- res$summary
  summary_out$Mode <- mode_label
  summary_out$Timestamp <- ts
  out_csv <- file.path(out_dir, paste0("filtered_summary_", ts, ".csv"))
  readr::write_csv(summary_out[,c("Mode","Tactic","MinStrength","MaxStrength","MitigationCount","Timestamp")], out_csv)
  if (!quiet) message("✅ Summary CSV saved → ", out_csv)

  # --- Compact map for callers + included tactics ----------------------------
  stage_map <- lapply(split(res$summary, res$summary$Tactic), function(r){
    list(min_strength=as.numeric(r$MinStrength),
         max_strength=as.numeric(r$MaxStrength),
         mean_strength=as.numeric((r$MinStrength+r$MaxStrength)/2),
         mitigation_count=as.integer(r$MitigationCount))
  })
  included_tactics <- as.character(res$summary$Tactic)

  list(
    detail=res$detail,
    summary=res$summary,
    included_tactics = included_tactics,
    stage_map = stage_map,
    impact_controls=impact_controls,
    relevance_metadata = list(mode = mode_label, included_tactics = included_tactics, timestamp = ts),
    output_dir = out_dir
  )
}

# ============================================================================
# CLI
# ============================================================================
main <- function(){
  option_list <- list(
    make_option(c("-d","--dataset"), type="character", default="enterprise-attack.json", help="MITRE dataset path [default %default]"),
    make_option(c("-s","--strengths"), type="character", default="mitigation_control_strengths.csv", help="Mitigation strengths CSV [default %default]"),
    make_option(c("-r","--use-relevance"), action="store_true", default=FALSE, help="Enable relevance filtering"),
    make_option(c("-f","--relevance-file"), type="character", default="technique_relevance.csv", help="Relevance CSV path [default %default]"),
    make_option(c("-n","--no-figure"), action="store_true", default=FALSE, help="Skip dashboard figure"),
    make_option(c("-x","--show-figure"), action="store_true", default=FALSE, help="Open dashboard HTML after generation"),
    make_option(c("-o","--output-dir"), type="character", default=NULL, help="Override output directory"),
    make_option(c("-q","--quiet"), action="store_true", default=FALSE, help="Suppress console messages")
  )
  opt <- parse_args(OptionParser(option_list = option_list))

  if (!opt$quiet) {
    cat("───────────────────────────────────────────────\n")
    cat("MITRE CONTROL STRENGTH DASHBOARD (R)\n")
    cat("Dataset:", opt$dataset, "\n")
    cat("Strengths:", opt$strengths, "\n")
    cat("Relevance:", ifelse(opt$`use-relevance`, paste0("Filtered (", opt$`relevance-file`, ")"), "Full"), "\n")
    cat("Output dir:", opt$`output-dir` %||% paste0("output_", format(Sys.Date(), "%Y-%m-%d")), "\n")
    cat("───────────────────────────────────────────────\n")
  }

  get_mitre_tactic_strengths(dataset_path = opt$dataset,
                             csv_path = opt$strengths,
                             use_relevance = isTRUE(opt$`use-relevance`),
                             relevance_file = opt$`relevance-file`,
                             build_figure = !isTRUE(opt$`no-figure`),
                             output_dir = opt$`output-dir`,
                             quiet = opt$quiet,
                             show_figure = isTRUE(opt$`show-figure`))
}
# Old (bad for sourcing):
# if (identical(environment(), globalenv())) main()

# New (prevents auto-CLI when sourced by the model):
if (identical(environment(), globalenv()) && is.null(getOption("MITRE_DASH_IMPORT"))) {
  main()
}
