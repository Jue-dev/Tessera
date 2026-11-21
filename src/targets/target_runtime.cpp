#include "tessera/targets/target_runtime.hpp"

#include <algorithm>
#include <format>
#include <new>
#include <utility>

#include "tessera/pattern/pattern.hpp"
#include "tessera/resolver/resolver.hpp"
#include "tessera/rtti/discovery.hpp"
#include "tessera/rtti/python_bridge.hpp"
#include "tessera/rtti/rtti.hpp"
#include "tessera/scanner/scanner.hpp"
#include "tessera/utility/bytes.hpp"
#include "tessera/utility/string.hpp"

namespace tessera::targets {

void AddressResolver::set_modules(std::vector<TargetModuleContext> modules) {
    modules_ = std::move(modules);
    invalidate_session_cache();
}

void AddressResolver::invalidate_session_cache() noexcept {
    session_cache_.clear();
}

const TargetModuleContext* AddressResolver::find_loaded_module(
    std::string_view module_id) const noexcept {
    for (const auto& m : modules_) {
        if (m.module_id == module_id) {
            return &m;
        }
    }
    return nullptr;
}

namespace {

[[nodiscard]] std::optional<Section> find_section_in_ctx(const TargetModuleContext& ctx,
                                                         std::string_view sec_name) {
    for (const auto& s : ctx.custom_sections) {
        if (s.name == sec_name) {
            return s;
        }
    }
    if (ctx.pe_image.has_value()) {
        if (auto s = ctx.pe_image->find_section(sec_name)) {
            return *s;
        }
    }
    return std::nullopt;
}

[[nodiscard]] Result<std::vector<Address>> execute_recipe(const Process& process,
                                                          const TargetModuleContext& mod_ctx,
                                                          const ResolutionRecipe& recipe) {
    std::vector<Address> candidates;
    switch (recipe.strategy) {
        case ResolutionStrategy::Rva: {
            auto va = mod_ctx.range.at_rva(recipe.rva);
            if (!va) {
                return std::unexpected(va.error());
            }
            candidates.push_back(*va);
            return candidates;
        }
        case ResolutionStrategy::Export: {
            if (!mod_ctx.pe_image.has_value()) {
                return fail(ErrorCode::NotFound, "execute_recipe(export)", 0, "No PE image available");
            }
            auto exp = !recipe.export_name.empty()
                           ? mod_ctx.pe_image->find_export(recipe.export_name)
                           : mod_ctx.pe_image->find_export(recipe.export_ordinal);
            if (!exp) {
                return std::unexpected(exp.error());
            }
            if (exp->is_forwarded()) {
                return fail(ErrorCode::InvalidPe,
                            "execute_recipe(export)",
                            0,
                            "Export is a forwarder string");
            }
            auto va = mod_ctx.range.at_rva(exp->rva);
            if (!va) {
                return std::unexpected(va.error());
            }
            candidates.push_back(*va);
            return candidates;
        }
        case ResolutionStrategy::Pattern:
        case ResolutionStrategy::Relative: {
            auto pat = Pattern::parse(recipe.pattern);
            if (!pat) {
                return std::unexpected(pat.error());
            }
            AddressRange scan_range = mod_ctx.range;
            if (!recipe.section.empty()) {
                auto sec = find_section_in_ctx(mod_ctx, recipe.section);
                if (!sec) {
                    return fail(ErrorCode::NotFound,
                                "execute_recipe(pattern)",
                                0,
                                "Specified section not found in module");
                }
                scan_range = sec->range();
            }
            Scanner scanner{process};
            auto scan_res = scanner.scan(scan_range, *pat);
            if (!scan_res) {
                return std::unexpected(scan_res.error());
            }
            for (const Address hit : scan_res->hits) {
                if (recipe.strategy == ResolutionStrategy::Relative) {
                    auto rel_pa = ProcessAddress{process, hit}
                                      .cursor()
                                      .offset(recipe.result_offset)
                                      .rel32(recipe.rel_disp_offset, recipe.rel_instr_len)
                                      .address();
                    if (rel_pa) {
                        candidates.push_back(*rel_pa);
                    }
                } else {
                    if (auto off_addr = hit.offset(recipe.result_offset)) {
                        candidates.push_back(*off_addr);
                    }
                }
            }
            return candidates;
        }
        case ResolutionStrategy::PointerChain: {
            auto base_va = mod_ctx.range.at_rva(recipe.rva);
            if (!base_va) {
                return std::unexpected(base_va.error());
            }
            auto resolved = ProcessAddress{process, *base_va}
                                .cursor()
                                .pointer_chain(recipe.pointer_offsets)
                                .address();
            if (!resolved) {
                return std::unexpected(resolved.error());
            }
            candidates.push_back(*resolved);
            return candidates;
        }
        case ResolutionStrategy::Field: {
            auto base_va = mod_ctx.range.at_rva(recipe.rva);
            if (!base_va) {
                return std::unexpected(base_va.error());
            }
            auto field_va = base_va->offset(recipe.result_offset);
            if (!field_va) {
                return std::unexpected(field_va.error());
            }
            candidates.push_back(*field_va);
            return candidates;
        }
        case ResolutionStrategy::RttiVTable: {
            const PeImage* pe_ptr = mod_ctx.pe_image ? &(*mod_ctx.pe_image) : nullptr;
            auto cat = rtti::RttiCatalog::discover_all(process, mod_ctx.range, pe_ptr);
            if (!cat) {
                return std::unexpected(cat.error());
            }
            auto cls = cat->find_class(recipe.class_name);
            if (!cls) {
                return std::unexpected(cls.error());
            }
            Address base_target = cls->vftable_address;
            if (recipe.vtable_index.has_value()) {
                if (*recipe.vtable_index >= cls->virtual_methods.size()) {
                    return fail(ErrorCode::OutOfRange,
                                "execute_recipe(rtti_vtable)",
                                0,
                                "vtableIndex out of range for class");
                }
                base_target = cls->virtual_methods[*recipe.vtable_index];
            }
            auto adj = base_target.offset(recipe.result_offset);
            if (!adj) {
                return std::unexpected(adj.error());
            }
            candidates.push_back(*adj);
            return candidates;
        }
        case ResolutionStrategy::StringXref: {
            auto strs = rtti::BinaryExplorer::scan_strings(process, mod_ctx.range, 3, true);
            if (!strs) {
                return std::unexpected(strs.error());
            }
            for (const auto& ds : *strs) {
                if (ds.value == recipe.string_literal) {
                    for (const Address xref_addr : ds.code_xrefs) {
                        if (auto adj = xref_addr.offset(recipe.result_offset)) {
                            candidates.push_back(*adj);
                        }
                    }
                }
            }
            return candidates;
        }
        case ResolutionStrategy::PythonMethod: {
            const PeImage* pe_ptr = mod_ctx.pe_image ? &(*mod_ctx.pe_image) : nullptr;
            auto py_cat = rtti::PythonBridgeScanner::discover_all(process, mod_ctx.range, pe_ptr);
            if (!py_cat) {
                return std::unexpected(py_cat.error());
            }
            auto meth = py_cat->find_method(recipe.python_method);
            if (!meth) {
                return std::unexpected(meth.error());
            }
            auto adj = meth->cpp_function_address.offset(recipe.result_offset);
            if (!adj) {
                return std::unexpected(adj.error());
            }
            candidates.push_back(*adj);
            return candidates;
        }
    }
    return candidates;
}

} // namespace

ValidationReport AddressResolver::run_validation_checks(const TargetModuleContext& mod_ctx,
                                                        const AddressEntry& entry,
                                                        Address candidate,
                                                        bool is_compatible_build) const {
    ValidationReport report{};
    report.all_required_passed = true;
    MemoryReader reader{process_};

    for (const auto& rule : entry.validation.rules) {
        ValidationCheckResult chk{};
        chk.rule = rule.kind;
        chk.required = rule.required;

        switch (rule.kind) {
            case ValidationRuleKind::ModuleRange: {
                if (mod_ctx.range.contains(candidate)) {
                    chk.status = CheckStatus::Passed;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Candidate address lies outside module address range";
                }
                break;
            }
            case ValidationRuleKind::Section: {
                auto sec = find_section_in_ctx(mod_ctx, rule.value);
                if (sec && sec->range().contains(candidate)) {
                    chk.status = CheckStatus::Passed;
                    report.has_independent_check = true;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = std::format("Candidate does not lie within section '{}'", rule.value);
                }
                break;
            }
            case ValidationRuleKind::MemoryReadable: {
                const std::uint64_t sz = (std::max)(entry.value.size, 1u);
                auto ok_r = reader.is_readable(AddressRange{candidate, sz});
                if (ok_r && *ok_r) {
                    chk.status = CheckStatus::Passed;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Candidate memory range is not readable";
                }
                break;
            }
            case ValidationRuleKind::MemoryWritable: {
                const std::uint64_t sz = (std::max)(entry.value.size, 1u);
                auto ok_w = reader.is_writable(AddressRange{candidate, sz});
                if (ok_w && *ok_w) {
                    chk.status = CheckStatus::Passed;
                    report.has_independent_check = true;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Candidate memory range is not writable";
                }
                break;
            }
            case ValidationRuleKind::MemoryExecutable: {
                auto ok_x = reader.is_executable(AddressRange{candidate, 1});
                if (ok_x && *ok_x) {
                    chk.status = CheckStatus::Passed;
                    report.has_independent_check = true;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Candidate memory is not executable";
                }
                break;
            }
            case ValidationRuleKind::ExpectedBytes: {
                auto pat = Pattern::parse(rule.value);
                if (!pat) {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Invalid expected_bytes pattern";
                    break;
                }
                if (is_compatible_build && entry.fallback.has_value() &&
                    entry.fallback->strategy == ResolutionStrategy::Pattern &&
                    rule.value != entry.fallback->pattern) {
                    report.has_independent_check = true;
                }
                auto bytes = reader.read_bytes(candidate, pat->size());
                if (bytes && pat->matches(*bytes)) {
                    chk.status = CheckStatus::Passed;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Bytes at candidate address do not match expected_bytes";
                }
                break;
            }
            case ValidationRuleKind::SecondarySignature: {
                auto pat = Pattern::parse(rule.value);
                auto sec_addr = candidate.offset(rule.relative_offset);
                if (!pat || !sec_addr) {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Invalid secondary_signature parameters";
                    break;
                }
                auto bytes = reader.read_bytes(*sec_addr, pat->size());
                if (bytes && pat->matches(*bytes)) {
                    chk.status = CheckStatus::Passed;
                    report.has_independent_check = true;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Secondary signature check failed";
                }
                break;
            }
            case ValidationRuleKind::PointerSanity: {
                auto ptr_val = reader.read_pointer(candidate);
                const std::uint64_t align_mask = (process_.pointer_size() == 8) ? 7ULL : 3ULL;
                if (ptr_val && !ptr_val->is_null() && ((ptr_val->value() & align_mask) == 0) &&
                    ptr_val->value() >= 0x10000ULL &&
                    ptr_val->value() <= process_.info().max_application_address) {
                    auto target_readable = reader.is_readable(AddressRange{*ptr_val, 1});
                    if (target_readable && *target_readable) {
                        chk.status = CheckStatus::Passed;
                        report.has_independent_check = true;
                    } else {
                        chk.status = CheckStatus::Failed;
                        chk.reason = "Dereferenced pointer points to unreadable memory";
                    }
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Pointer value failed null/alignment/range sanity check";
                }
                break;
            }
            case ValidationRuleKind::ValueRange: {
                auto val32 = reader.read<std::int32_t>(candidate);
                if (val32 && *val32 >= rule.min_value && *val32 <= rule.max_value) {
                    chk.status = CheckStatus::Passed;
                    report.has_independent_check = true;
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Value at candidate address is outside allowed range";
                }
                break;
            }
            case ValidationRuleKind::InstructionShape: {
                auto pat = Pattern::parse(rule.value);
                if (pat) {
                    auto bytes = reader.read_bytes(candidate, pat->size());
                    if (bytes && pat->matches(*bytes)) {
                        chk.status = CheckStatus::Passed;
                        report.has_independent_check = true;
                    } else {
                        chk.status = CheckStatus::Failed;
                        chk.reason = "Instruction shape mismatch";
                    }
                } else {
                    chk.status = CheckStatus::Failed;
                    chk.reason = "Invalid instruction_shape pattern";
                }
                break;
            }
        }

        if (chk.required && chk.status != CheckStatus::Passed) {
            report.all_required_passed = false;
        }
        report.checks.push_back(std::move(chk));
    }

    if (entry.validation.rules.empty()) {
        report.all_required_passed = false;
    }
    return report;
}

ResolutionOutcome AddressResolver::resolve_entry(TargetProfile& profile,
                                                 std::string_view entry_id,
                                                 PersistPolicy persist_policy,
                                                 TargetProfileStore* store) {
    return resolve_entry(profile, entry_id, persist_policy, store, nullptr);
}

ResolutionOutcome AddressResolver::resolve_entry(TargetProfile& profile,
                                                 std::string_view entry_id,
                                                 PersistPolicy persist_policy,
                                                 TargetProfileStore* store,
                                                 ResolutionTrace* trace) {
    ResolutionOutcome outcome{};
    if (trace != nullptr) {
        trace->steps.clear();
    }
    const auto begin_stage = [&](std::string_view name) {
        if (trace == nullptr) {
            return;
        }
        if (!trace->steps.empty()) {
            trace->steps.back().status = ResolutionStatus::CandidateFound;
            trace->steps.back().detail = "Stage completed";
        }
        trace->steps.push_back(ResolutionTraceStep{
            .stage = std::string(name),
            .status = ResolutionStatus::NotFound,
            .detail = "Stage started",
        });
    };
    const auto finish = [&]() {
        if (trace != nullptr && !trace->steps.empty()) {
            trace->steps.back().status = outcome.status;
            if (outcome.from_session_cache) {
                trace->steps.back().detail = "Resolved from verified session cache";
            } else {
                switch (outcome.status) {
                case ResolutionStatus::VerifiedExactBuild:
                    trace->steps.back().detail = "Exact-build candidate passed required checks";
                    break;
                case ResolutionStatus::VerifiedCompatibleBuild:
                    trace->steps.back().detail =
                        "Compatible-build candidate passed required and independent checks";
                    break;
                case ResolutionStatus::NeedsReview:
                    trace->steps.back().detail =
                        "Candidate needs review because independent verification or policy approval is missing";
                    break;
                case ResolutionStatus::Ambiguous:
                    trace->steps.back().detail = "More than one candidate matched";
                    break;
                case ResolutionStatus::Stale:
                    trace->steps.back().detail = "Candidate recipe was unavailable or failed required validation";
                    break;
                case ResolutionStatus::NotFound:
                    trace->steps.back().detail = "No matching build, module, or candidate was found";
                    break;
                case ResolutionStatus::IncompatibleTarget:
                    trace->steps.back().detail = "Target architecture or loaded module is incompatible";
                    break;
                case ResolutionStatus::CandidateFound:
                    trace->steps.back().detail = "A candidate was found but is not verified";
                    break;
                }
            }
        }
        return outcome;
    };
    begin_stage("Architecture compatibility");
    const TargetArch proc_arch =
        (process_.architecture() == Architecture::X64) ? TargetArch::X64 : TargetArch::X86;

    // 1. Verify target architecture compatibility
    const bool arch_supported =
        std::find(profile.application.supported_architectures.begin(),
                  profile.application.supported_architectures.end(),
                  proc_arch) != profile.application.supported_architectures.end();
    if (!arch_supported) {
        outcome.status = ResolutionStatus::IncompatibleTarget;
        return finish();
    }

    begin_stage("Verified session cache");
    // 2. Check session cache first (valid only if PID, profile revision, module base, and SHA256 match)
    for (const auto& cached : session_cache_) {
        if (cached.entry_id == entry_id && cached.pid == process_.pid() &&
            cached.profile_revision == profile.revision) {
            const auto* mod_ctx = find_loaded_module(cached.module_id);
            if (mod_ctx != nullptr && mod_ctx->range.begin() == cached.module_base &&
                mod_ctx->fingerprint.sha256 == cached.module_sha256) {
                outcome.status = cached.verified.status();
                outcome.report = cached.report;
                outcome.candidate_address = cached.verified.address();
                outcome.candidate_rva = cached.verified.rva();
                outcome.from_session_cache = true;
                outcome.verified_ = cached.verified;
                return finish();
            }
        }
    }

    begin_stage("Build and module selection");
    // 3. Find matching exact build or compatible build of the same architecture
    const TargetBuild* exact_build = nullptr;
    const TargetBuild* fallback_build = nullptr;

    for (const auto& b : profile.builds) {
        if (b.architecture != proc_arch) {
            continue;
        }
        const auto* entry = b.find_address(entry_id);
        if (entry == nullptr) {
            continue;
        }
        const auto* loaded_mod = find_loaded_module(entry->module_id);
        if (loaded_mod == nullptr) {
            continue;
        }
        const auto* expected_mod_fp = b.find_module(entry->module_id);
        if (expected_mod_fp != nullptr && loaded_mod->fingerprint.matches_strong(*expected_mod_fp)) {
            exact_build = &b;
            break;
        }
        if (fallback_build == nullptr) {
            fallback_build = &b;
        }
    }

    const TargetBuild* selected_build = exact_build ? exact_build : fallback_build;
    if (selected_build == nullptr) {
        // Check if entry exists in any build of a different architecture -> IncompatibleTarget
        for (const auto& b : profile.builds) {
            if (b.find_address(entry_id) != nullptr) {
                outcome.status = ResolutionStatus::IncompatibleTarget;
                return finish();
            }
        }
        outcome.status = ResolutionStatus::NotFound;
        return finish();
    }

    const AddressEntry* entry = selected_build->find_address(entry_id);
    const TargetModuleContext* mod_ctx = find_loaded_module(entry->module_id);
    if (mod_ctx == nullptr) {
        outcome.status = ResolutionStatus::IncompatibleTarget;
        return finish();
    }

    begin_stage("Exact-build primary recipe");
    // 4. If exact build matched, try primary recipe first and validate
    if (exact_build != nullptr) {
        auto primary_cands = execute_recipe(process_, *mod_ctx, entry->primary);
        if (primary_cands && !primary_cands->empty()) {
            if (primary_cands->size() > 1) {
                outcome.status = ResolutionStatus::Ambiguous;
                return finish();
            }
            const Address cand = primary_cands->front();
            outcome.candidate_address = cand;
            if (auto rva = mod_ctx->range.to_rva(cand)) {
                outcome.candidate_rva = *rva;
            }
            outcome.report = run_validation_checks(*mod_ctx, *entry, cand, false);
            if (outcome.report.all_required_passed) {
                outcome.status = ResolutionStatus::VerifiedExactBuild;
                const Rva verified_rva = outcome.candidate_rva.value_or(Rva{0});
                outcome.verified_ = VerifiedAddress{cand,
                                                    verified_rva,
                                                    entry->id,
                                                    entry->module_id,
                                                    ResolutionStatus::VerifiedExactBuild};
                session_cache_.push_back(SessionCacheItem{
                    .pid = process_.pid(),
                    .profile_revision = profile.revision,
                    .entry_id = entry->id,
                    .module_id = entry->module_id,
                    .module_base = mod_ctx->range.begin(),
                    .module_sha256 = mod_ctx->fingerprint.sha256,
                    .verified = *outcome.verified_,
                    .report = outcome.report,
                });
                return finish();
            }
            // Exact build primary RVA failed required checks -> Stale if no fallback, or try fallback
            if (!entry->fallback.has_value()) {
                outcome.status = ResolutionStatus::Stale;
                return finish();
            }
        } else if (!entry->fallback.has_value()) {
            outcome.status = ResolutionStatus::Stale;
            return finish();
        }
    }

    begin_stage("Fallback and compatible-build recipe");
    // 5. Fallback / compatible-build resolution
    const ResolutionRecipe& compat_recipe =
        entry->fallback.has_value() ? *entry->fallback : entry->primary;
    if (compat_recipe.strategy == ResolutionStrategy::Rva && exact_build == nullptr) {
        // Raw RVA cannot be trusted on a different build without a pattern/export fallback
        outcome.status = ResolutionStatus::Stale;
        return finish();
    }

    auto compat_cands = execute_recipe(process_, *mod_ctx, compat_recipe);
    if (!compat_cands || compat_cands->empty()) {
        outcome.status = (exact_build != nullptr) ? ResolutionStatus::Stale : ResolutionStatus::NotFound;
        return finish();
    }
    if (compat_cands->size() > 1) {
        outcome.status = ResolutionStatus::Ambiguous;
        return finish();
    }

    const Address cand = compat_cands->front();
    outcome.candidate_address = cand;
    if (auto rva = mod_ctx->range.to_rva(cand)) {
        outcome.candidate_rva = *rva;
    }

    outcome.report = run_validation_checks(*mod_ctx, *entry, cand, true);
    if (compat_recipe.strategy == ResolutionStrategy::RttiVTable ||
        compat_recipe.strategy == ResolutionStrategy::StringXref ||
        compat_recipe.strategy == ResolutionStrategy::PythonMethod) {
        outcome.report.has_independent_check = true;
    }
    if (!outcome.report.all_required_passed) {
        outcome.status = (exact_build != nullptr) ? ResolutionStatus::Stale : ResolutionStatus::CandidateFound;
        return finish();
    }

    // §17.4 Rule: On a new/compatible build, a single pattern match alone is never sufficient;
    // at least one independent secondary/semantic check must pass, otherwise result is at most NeedsReview.
    if (!outcome.report.has_independent_check || !entry->validation.allow_compatible_build) {
        outcome.status = ResolutionStatus::NeedsReview;
        return finish();
    }

    outcome.status = ResolutionStatus::VerifiedCompatibleBuild;
    const Rva verified_rva = outcome.candidate_rva.value_or(Rva{0});
    outcome.verified_ = VerifiedAddress{cand,
                                        verified_rva,
                                        entry->id,
                                        entry->module_id,
                                        ResolutionStatus::VerifiedCompatibleBuild};

    session_cache_.push_back(SessionCacheItem{
        .pid = process_.pid(),
        .profile_revision = profile.revision,
        .entry_id = entry->id,
        .module_id = entry->module_id,
        .module_base = mod_ctx->range.begin(),
        .module_sha256 = mod_ctx->fingerprint.sha256,
        .verified = *outcome.verified_,
        .report = outcome.report,
    });

    // 6. Auto-persist new TargetBuild if policy is AutoPersistVerified
    if (persist_policy == PersistPolicy::AutoPersistVerified && exact_build == nullptr) {
        begin_stage("Verified compatible-build persistence");
        TargetBuild new_build{};
        new_build.build_id = std::format(
            "auto-{}-{}",
            proc_arch == TargetArch::X64 ? "x64" : "x86",
            mod_ctx->fingerprint.sha256.empty() ? "mem" : mod_ctx->fingerprint.sha256.substr(0, 8));
        new_build.architecture = proc_arch;
        new_build.fingerprint.size_of_image = mod_ctx->fingerprint.size_of_image;
        new_build.fingerprint.timestamp = mod_ctx->fingerprint.timestamp;
        new_build.fingerprint.checksum = mod_ctx->fingerprint.checksum;
        new_build.fingerprint.sha256 = mod_ctx->fingerprint.sha256;
        new_build.modules.push_back(mod_ctx->fingerprint);

        AddressEntry persisted_entry = *entry;
        persisted_entry.primary = ResolutionRecipe{
            .strategy = ResolutionStrategy::Rva,
            .rva = verified_rva,
        };
        persisted_entry.audit = AuditRecord{
            .timestamp_utc = "2026-11-15T00:00:00Z",
            .source_build_id = selected_build->build_id,
            .strategy_used = "fallback_verified",
            .summary = "Automatically persisted verified compatible build",
        };
        new_build.addresses.push_back(std::move(persisted_entry));
        profile.builds.push_back(std::move(new_build));

        if (store != nullptr) {
            (void)store->save(profile);
        }
    }

    return finish();
}

} // namespace tessera::targets
