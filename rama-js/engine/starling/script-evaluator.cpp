#include "encode.h"
#include "extension-api.h"

#include <js/CompilationAndEvaluation.h>
#include <js/CompileOptions.h>
#include <js/SourceText.h>

#include <utility>

namespace rama::js_engine::script_evaluator {
namespace {

bool last_evaluation_failed_during_parse = false;

bool evaluate_script(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  last_evaluation_failed_during_parse = false;

  if (args.length() != 1) {
    JS_ReportErrorASCII(
        cx, "Rama script evaluation expects exactly one source argument");
    return false;
  }

  auto encoded = core::encode(cx, args.get(0));
  if (!encoded) {
    return false;
  }

  JS::SourceText<mozilla::Utf8Unit> source;
  if (!source.init(cx, std::move(encoded.ptr), encoded.len)) {
    return false;
  }

  JS::CompileOptions options(cx);
  options.setFileAndLine("<rama-js>", 1);
  options.setForceFullParse();

  JS::RootedScript script(cx, JS::Compile(cx, options, source));
  if (!script) {
    last_evaluation_failed_during_parse = true;
    return false;
  }

  return JS_ExecuteScript(cx, script, args.rval());
}

bool take_parse_failure(JSContext *cx, unsigned argc, JS::Value *vp) {
  JS::CallArgs args = JS::CallArgsFromVp(argc, vp);
  if (args.length() != 0) {
    JS_ReportErrorASCII(cx, "Rama parse-failure query expects no arguments");
    return false;
  }

  args.rval().setBoolean(
      std::exchange(last_evaluation_failed_during_parse, false));
  return true;
}

} // namespace

bool install(api::Engine *engine) {
  return JS_DefineFunction(engine->cx(), engine->global(),
                           "__rama_evaluate_script__", evaluate_script, 1, 0) &&
         JS_DefineFunction(engine->cx(), engine->global(),
                           "__rama_take_parse_failure__", take_parse_failure, 0,
                           0);
}

} // namespace rama::js_engine::script_evaluator
