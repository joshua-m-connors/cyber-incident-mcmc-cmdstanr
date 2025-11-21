#!/usr/bin/env Rscript
# Build technique_relevance.csv
# Version: v1.0
# Description: Creates a checklist of ATT&CK tactics/techniques with a Relevant column, optionally auto-marked by procedures/campaigns.
suppressPackageStartupMessages({
  library(jsonlite); library(dplyr); library(readr); library(tidyr)
  library(stringr); library(optparse)
})

`%||%` <- function(a,b){ if (is.null(a)) b else a }

TACTIC_ORDER <- c("initial-access","execution","persistence","privilege-escalation",
                  "defense-evasion","credential-access","discovery","lateral-movement",
                  "collection","command-and-control","exfiltration","impact")
TACTIC_LABELS <- c(
  "initial-access"="Initial Access", "execution"="Execution","persistence"="Persistence",
  "privilege-escalation"="Privilege Escalation","defense-evasion"="Defense Evasion",
  "credential-access"="Credential Access","discovery"="Discovery","lateral-movement"="Lateral Movement",
  "collection"="Collection","command-and-control"="Command and Control",
  "exfiltration"="Exfiltration","impact"="Impact"
)

make_output_dir <- function(prefix="output", override=NULL, quiet=FALSE){
  out_dir <- override
  if (is.null(out_dir) || !nzchar(out_dir)) out_dir <- file.path(getwd(), paste0(prefix, "_", format(Sys.Date(), "%Y-%m-%d")))
  if (!dir.exists(out_dir)) dir.create(out_dir, recursive = TRUE)
  if (!quiet) message("📁 Output directory: ", out_dir)
  out_dir
}

find_local_json <- function(){
  cands <- c("enterprise-attack.json","enterprise_attack.json","mitre-enterprise-attack.json","mitre_attack_enterprise.json")
  p <- cands[file.exists(cands)]
  if (length(p)) p[[1]] else NULL
}

extract_mitre_id <- function(refs){
  if (!is.list(refs)) return(NA_character_)
  for (r in refs) {
    if (r$source_name == "mitre-attack") return(r$external_id %||% NA_character_)
  }
  NA_character_
}

normalize_phase <- function(x) str_trim(tolower(x))

load_attack_patterns <- function(bundle_objs){
  rows <- lapply(bundle_objs, function(obj){
    if (obj$type != "attack-pattern") return(NULL)
    name <- obj$name; ext_id <- extract_mitre_id(obj$external_references)
    kcp <- obj$kill_chain_phases
    if (is.null(name) || is.null(kcp)) return(NULL)
    lapply(kcp, function(ph){
      if (ph$kill_chain_name != "mitre-attack") return(NULL)
      tactic_slug <- normalize_phase(ph$phase_name)
      if (!(tactic_slug %in% TACTIC_ORDER)) return(NULL)
      tibble(tid=ext_id, tname=name, tactic=tactic_slug)
    }) %>% bind_rows()
  })
  bind_rows(rows)
}

build_rows_by_tactic <- function(tech_tbl, dedupe_names=FALSE){
  by_tac <- tech_tbl %>% group_by(tactic) %>% summarise(items=list(tibble(tid=tid,tname=tname)), .groups="drop")
  if (nrow(by_tac) == 0) return(list())
  res <- setNames(vector("list", length(TACTIC_ORDER)), TACTIC_ORDER)
  for (i in seq_len(nrow(by_tac))) {
    tac <- by_tac$tactic[[i]]
    items <- by_tac$items[[i]] %>% arrange(tolower(tname))
    if (isTRUE(dedupe_names)) items <- items %>% distinct(tolower(tname), .keep_all = TRUE)
    res[[tac]] <- items
  }
  res
}

find_objects_by_name_or_id <- function(bundle_objs, name_or_id, valid_types){
  Filter(function(o){
    o$type %in% valid_types && (identical(o$id, name_or_id) || grepl(tolower(name_or_id), tolower(o$name %||% ""), fixed=TRUE))
  }, bundle_objs)
}

find_campaign_by_external_id <- function(bundle_objs, cid){
  for (o in bundle_objs) {
    if (o$type != "campaign") next
    refs <- o$external_references
    if (is.list(refs)) {
      for (r in refs) {
        if (r$source_name == "mitre-attack" && r$external_id == cid) return(o)
      }
    }
  }
  NULL
}

collect_techniques_for_sources <- function(bundle_objs, source_ids){
  id_to_tech <- list()
  for (o in bundle_objs) if (o$type == "attack-pattern") id_to_tech[[o$id]] <- list(mitre_id=extract_mitre_id(o$external_references), name=o$name)
  technique_ids <- character(); technique_desc <- list()
  for (rel in bundle_objs) {
    if (rel$type != "relationship") next
    if (rel$relationship_type != "uses") next
    if (rel$source_ref %in% source_ids && startsWith(rel$target_ref, "attack-pattern--")) {
      t <- id_to_tech[[rel$target_ref]]
      if (!is.null(t) && !is.na(t$mitre_id)) {
        technique_ids <- unique(c(technique_ids, t$mitre_id))
        technique_desc <- append(technique_desc, list(list(technique_id=t$mitre_id, technique_name=t$name, relationship_description = rel$description %||% "")))
      }
    }
  }
  list(ids=unique(technique_ids), desc=technique_desc)
}

write_csv_matrix <- function(by_tactic, out_path, auto_ids=character(), mark_all="none"){
  mark_value <- ifelse(mark_all == "all", "X", "")
  con <- file(out_path, open="wt", encoding="UTF-8"); on.exit(close(con), add=TRUE)
  writeLines("Tactic,Technique ID,Technique,Relevant", con)
  for (tac in TACTIC_ORDER) {
    items <- by_tactic[[tac]]
    if (is.null(items) || nrow(items) == 0) next
    for (i in seq_len(nrow(items))) {
      tid <- items$tid[[i]]; tname <- items$tname[[i]]
      rel <- ifelse(!is.na(tid) && tid %in% auto_ids, "X", mark_value)
      line <- paste0('"', TACTIC_LABELS[[tac]], '","', tid %||% '', '","', gsub('"','""',tname), '","', rel, '"')
      writeLines(line, con)
    }
  }
}

main <- function(){
  option_list <- list(
    make_option(c("-e","--enterprise-json"), type="character", default=NULL,
                help="Path to MITRE Enterprise JSON (auto-detect if omitted)"),
    make_option(c("-m","--mark-all"), type="character", default="none",
                help="Mark all techniques as relevant: 'all' or 'none' [default %default]"),
    make_option(c("-p","--procedure"), type="character", action="append", default=NULL,
                help="Procedure name(s) (APT/Malware/Tool); may repeat"),
    make_option(c("-c","--campaign"), type="character", action="append", default=NULL,
                help="Campaign ID(s), e.g., C0017; may repeat"),
    make_option(c("-d","--dedupe-names"), action="store_true", default=FALSE, help="Dedupe identical technique names"),
    make_option(c("-s","--sort-techniques"), action="store_true", default=TRUE, help="Sort techniques alphabetically (default on)"),
    make_option(c("-o","--output-dir"), type="character", default=NULL, help="Override output directory"),
    make_option(c("-q","--quiet"), action="store_true", default=FALSE, help="Suppress console messages")
  )
  opt <- parse_args(OptionParser(option_list = option_list))

  path <- opt$`enterprise-json` %||% find_local_json()
  if (is.null(path)) stop("No MITRE Enterprise JSON found.", call.=FALSE)

  outdir <- make_output_dir(override = opt$`output-dir`, quiet = opt$quiet)

  if (!opt$quiet) {
    cat("───────────────────────────────────────────────\n")
    cat("TECHNIQUE RELEVANCE TEMPLATE (R)\n")
    cat("Dataset:", path, "\n")
    cat("Procedures:", paste(opt$procedure %||% character(), collapse=", "), "\n")
    cat("Campaigns:", paste(opt$campaign %||% character(), collapse=", "), "\n")
    cat("Mark all:", opt$`mark-all`, " | Dedupe:", isTRUE(opt$`dedupe-names`), " | Sort:", isTRUE(opt$`sort-techniques`), "\n")
    cat("Output dir:", outdir, "\n")
    cat("───────────────────────────────────────────────\n")
  }

  bundle <- fromJSON(path, simplifyVector = FALSE); objs <- bundle$objects
  tech_tbl <- load_attack_patterns(objs)
  grouped <- build_rows_by_tactic(tech_tbl, dedupe_names = isTRUE(opt$`dedupe-names`))

  auto_ids <- character(); evidence <- list()
  if (!is.null(opt$procedure)) {
    for (p in opt$procedure) {
      matches <- find_objects_by_name_or_id(objs, p, c("intrusion-set","malware","tool"))
      if (length(matches) == 0) next
      ids <- vapply(matches, function(m) m$id, "")
      res <- collect_techniques_for_sources(objs, ids)
      auto_ids <- unique(c(auto_ids, res$ids)); evidence <- append(evidence, list(list(procedure=p, techniques=res$desc)))
    }
  }
  if (!is.null(opt$campaign)) {
    for (cid in opt$campaign) {
      if (!grepl("^C\\d{4,5}$", cid, ignore.case = TRUE)) next
      camp <- find_campaign_by_external_id(objs, toupper(cid))
      if (is.null(camp)) next
      res <- collect_techniques_for_sources(objs, c(camp$id))
      auto_ids <- unique(c(auto_ids, res$ids)); evidence <- append(evidence, list(list(campaign=toupper(cid), techniques=res$desc)))
    }
  }

  csv_path <- file.path(outdir, "technique_relevance.csv")
  write_csv_matrix(grouped, csv_path, auto_ids = auto_ids, mark_all = opt$`mark-all`)
  if (!opt$quiet) message("✅ Wrote: ", csv_path)

  if (length(evidence)) {
    ev_path <- file.path(outdir, "technique_relevance_evidence.json")
    jsonlite::write_json(list(procedures_used = opt$procedure %||% list(),
                              campaigns_used = opt$campaign %||% list(),
                              auto_marked_count = length(auto_ids),
                              evidence = evidence),
                         ev_path, pretty = TRUE, auto_unbox = TRUE)
    if (!opt$quiet) message("📝 Wrote: ", ev_path)
  }
}

if (identical(environment(), globalenv())) main()
