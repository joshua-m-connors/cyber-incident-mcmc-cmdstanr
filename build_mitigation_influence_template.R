#!/usr/bin/env Rscript
# MITRE ATT&CK Mitigation Influence Template Builder
# Version: v1.0
# Description: Reads enterprise-attack.json (STIX), maps mitigations -> techniques -> tactics,
# computes influence weights and default control ranges, writes mitigation_influence_template.csv.
suppressPackageStartupMessages({
  library(jsonlite); library(dplyr); library(stringr); library(readr); library(tidyr); library(optparse)
})

`%||%` <- function(a,b){ if (is.null(a)) b else a }

make_output_dir <- function(prefix="output", override=NULL, quiet=FALSE){
  out_dir <- override
  if (is.null(out_dir) || !nzchar(out_dir)) {
    out_dir <- file.path(getwd(), paste0(prefix, "_", format(Sys.Date(), "%Y-%m-%d")))
  }
  if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
  if (!quiet) message("📁 Output directory: ", out_dir)
  out_dir
}

load_stix <- function(path="enterprise-attack.json") {
  dat <- fromJSON(path, simplifyVector = FALSE)
  objs <- if (!is.null(dat$objects)) dat$objects else dat
  techniques <- Filter(function(o) is.list(o) && o$type == "attack-pattern", objs)
  mitigations <- Filter(function(o) is.list(o) && o$type == "course-of-action", objs)
  relationships <- Filter(function(o) is.list(o) && o$type == "relationship" && o$relationship_type == "mitigates", objs)
  list(techniques=techniques, mitigations=mitigations, relationships=relationships)
}

ext_mit_id <- function(mobj) {
  refs <- mobj$external_references
  if (is.null(refs) || !is.list(refs)) return(NA_character_)
  ids <- vapply(refs, function(r) { id <- r$external_id; if (is.character(id) && startsWith(id, "M")) id else NA_character_ }, FUN.VALUE = character(1))
  ids <- ids[!is.na(ids)]
  if (length(ids) == 0) NA_character_ else ids[[1]]
}

build_template <- function(stix, quiet=FALSE) {
  rel_df <- tibble(
    source_ref = vapply(stix$relationships, function(r) r$source_ref %||% "", ""),
    target_ref = vapply(stix$relationships, function(r) r$target_ref %||% "", "")
  ) %>%
    filter(startsWith(source_ref, "course-of-action"),
           startsWith(target_ref, "attack-pattern")) %>%
    distinct()

  tech_rows <- lapply(stix$techniques, function(tobj){
    kcp <- tobj$kill_chain_phases
    if (is.null(kcp)) return(NULL)
    rows <- lapply(kcp, function(ph){
      if (!identical(ph$kill_chain_name, "mitre-attack")) return(NULL)
      tactic <- ph$phase_name
      if (is.null(tactic)) return(NULL)
      tibble(tech_id = tobj$id, tactic = str_to_title(str_replace_all(tactic, "-", " ")))
    })
    bind_rows(rows)
  })
  tech_kc <- bind_rows(tech_rows)

  tech_counts <- rel_df %>% count(source_ref, name="n_tech")
  if (nrow(tech_counts) == 0) return(tibble())
  max_count <- max(tech_counts$n_tech)

  default_ranges <- list(c(30,70), c(35,65), c(40,60))
  set.seed(42)

  rows <- lapply(stix$mitigations, function(mobj){
    name <- mobj$name %||% "Unknown"
    mid <- ext_mit_id(mobj)
    if (is.na(mid) || tolower(trimws(name)) == "do not mitigate") return(NULL)
    linked <- rel_df %>% filter(source_ref == mobj$id)
    techniques_mitigated <- nrow(linked)
    tacts <- linked %>% left_join(tech_kc, by = c("target_ref"="tech_id")) %>%
      filter(!is.na(tactic)) %>% distinct(tactic) %>% nrow()
    weight <- ifelse(max_count > 0, round(techniques_mitigated / max_count, 3), 0)
    rng <- default_ranges[[sample.int(length(default_ranges), 1)]]
    lo <- rng[1]; hi <- rng[2]
    if (tolower(trimws(name)) == "audit") { lo <- floor(lo*0.5); hi <- floor(hi*0.5) }
    tibble(Mitigation_ID=mid, Mitigation_Name=name, Techniques_Mitigated=techniques_mitigated,
           Tactics_Covered=tacts, Weight=weight, Control_Min=lo, Control_Max=hi)
  })
  df <- bind_rows(rows)
  if (nrow(df)) df <- df %>% arrange(desc(Weight), desc(Techniques_Mitigated), desc(Tactics_Covered))
  df
}

main <- function(){
  option_list <- list(
    make_option(c("-d","--dataset"), type="character", default="enterprise-attack.json",
                help="Path to MITRE ATT&CK JSON [default %default]"),
    make_option(c("-o","--output-dir"), type="character", default=NULL,
                help="Override output directory (default output_YYYY-MM-DD)"),
    make_option(c("-q","--quiet"), action="store_true", default=FALSE, help="Suppress console messages")
  )
  opt <- parse_args(OptionParser(option_list = option_list))

  out_dir <- make_output_dir(override = opt$`output-dir`, quiet = opt$quiet)

  if (!file.exists(opt$dataset)) stop("Dataset not found: ", opt$dataset, call.=FALSE)

  if (!opt$quiet) {
    cat("───────────────────────────────────────────────\n")
    cat("MITIGATION INFLUENCE TEMPLATE BUILDER (R)\n")
    cat("Dataset:", opt$dataset, "\n")
    cat("Output dir:", out_dir, "\n")
    cat("───────────────────────────────────────────────\n")
  }

  stix <- load_stix(opt$dataset)
  df <- build_template(stix, quiet = opt$quiet)

  out_csv <- file.path(getwd(), "mitigation_influence_template.csv")
  if (nrow(df)) {
    write_csv(df, out_csv)
    if (!opt$quiet) message("✅ Saved ", nrow(df), " mitigations to: ", out_csv)
  } else {
    if (!opt$quiet) message("⚠️ No mitigations available.")
  }

  log_path <- file.path(out_dir, paste0("mitigation_template_build_log_", format(Sys.time(), "%Y-%m-%d_%H-%M-%S"), ".txt"))
  con <- file(log_path, open="wt", encoding="UTF-8")
  writeLines(c(
    paste("MITRE dataset:", opt$dataset),
    paste("Mitigation rows:", nrow(df)),
    paste("CSV path:", out_csv)
  ), con); close(con)
  if (!opt$quiet) message("📝 Log saved to: ", log_path)
}

if (identical(environment(), globalenv())) main()
