if(PROJECT_NAME STREQUAL "ComponentizeJS")
    add_builtin(rama::js_engine::script_evaluator
        SRC "${CMAKE_CURRENT_LIST_DIR}/script-evaluator.cpp")
endif()
