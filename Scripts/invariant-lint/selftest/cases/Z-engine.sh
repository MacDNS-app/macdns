# The lint engine itself. Both cases here are regressions of defects that shipped
# green: a broken lint that still looks like a working one.

# REGRESSION: `close` is a reserved awk builtin. Using it as a parameter name
# made every scanner a syntax error, and the rules turned that empty output into
# a well-formed FAIL — findings invented from a program that never ran. A crashed
# scanner is an internal error, and must never surface as a violation.
begin "engine reports a crashed scanner as an error, never as a finding"
broken=$(clone_lint broken-awk)
printf '\nfunction il_reserved(s, close) { return s }\n' >>"$broken/lib/awklib.awk"
expect_in "$broken" J07 error "scanner failed" "FAIL"

# REGRESSION: the runner globbed rules/*.sh, so an awk producer parked in rules/
# was never executed and the suite reported green for an invariant nobody
# checked. Discovery now walks the directory and refuses anything it cannot run.
begin "engine refuses a rule module it cannot execute"
inert=$(clone_lint inert-rule)
for stray in "$inert"/rules/*; do
    case "$(basename "$stray")" in
        J07*) ;;
        *) rm -f "$stray" ;;
    esac
done
printf 'BEGIN { }\n' >"$inert/rules/J99-producer.awk"
chmod -x "$inert/rules/J99-producer.awk"
expect_runner "$inert" error "not an executable rule module"

begin "engine confirms every module in rules/ ran"
whole=$(clone_lint whole-run)
for stray in "$whole"/rules/*; do
    case "$(basename "$stray")" in
        J07*) ;;
        *) rm -f "$stray" ;;
    esac
done
expect_runner "$whole" ok "module(s) in rules/ executed"
