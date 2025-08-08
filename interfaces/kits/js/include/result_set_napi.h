/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTERFACES_KITS_JS_RDB_INCLUDE_RESULT_SET_NAPI_H_
#define INTERFACES_KITS_JS_RDB_INCLUDE_RESULT_SET_NAPI_H_

#include <vector>

#include "medialibrary_napi_utils.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "result_set.h"
#include "napi_remote_object.h"
#include "datashare_helper.h"
#include "napi_error.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

using namespace OHOS::NativeRdb;

static const std::string RESULT_SET_NAPI_CLASS_NAME = "ResultSet";

class ResultSetNapi {
public:
    std::shared_ptr<ResultSet> resultSetPtr = nullptr;
    EXPORT static napi_value Init(napi_env env, napi_value exports);
    EXPORT static napi_value CreateResultSetNapi(napi_env env, std::shared_ptr<ResultSet> &resultSet,
                                                 JSAsyncContextOutput &asyncContext);
    explicit ResultSetNapi(std::shared_ptr<ResultSet> ptr);
    EXPORT ~ResultSetNapi();

private:
    EXPORT static void ResultSetNapiDestructor(napi_env env, void *nativeObject, void *finalize_hint);
    EXPORT static napi_value ResultSetNapiConstructor(napi_env env, napi_callback_info info);
    // NAPI Property declarations
    EXPORT static napi_value JSGetColumnCount(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetRowCount(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetRowIndex(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSIsAtLastRow(napi_env env, napi_callback_info info);
    // NAPI Method declarations
    EXPORT static napi_value JSGoToRow(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGoToFirstRow(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGoToNextRow(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetBlob(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetString(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetLong(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetDouble(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetBool(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetValue(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSGetRow(napi_env env, napi_callback_info info);
    EXPORT static napi_value JSClose(napi_env env, napi_callback_info info);

    napi_env env_;
    static thread_local napi_ref sResultSetConstructor_;
};
struct ResultSetAsyncContext : public NapiError {
    std::string networkId;
    std::string uri;
    string errorMsg;
    size_t argc;
    napi_value argv[NAPI_ARGC_MAX];
    napi_async_work work;
    napi_deferred deferred;
    napi_ref callbackRef;
    napi_value napiArrayBuffer;
    std::shared_ptr<NativeRdb::ResultSet> queryRet = nullptr;
    ResultSetNapi *objectInfo;
};
// c++变量转换js
template <typename T>
napi_value Convert2JSValue(napi_env env, const T &value)
{
    NAPI_ERR_LOG("No conversion implemented for this type, returning undefined");
    return nullptr;
}

template <typename T>
napi_value Convert2JSValue(napi_env env, const std::vector<T> &value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Napi_create_array_with_length failed");
        return jsValue;
    }
    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, Convert2JSValue(env, value[i]));
    }
    return jsValue;
}

template <typename... Types>
napi_value Convert2JSValue(napi_env env, const std::variant<Types...> &value)
{
    return std::visit(
        [&](const auto &v) -> napi_value {
            return Convert2JSValue(env, v);  // 这里会自动选择最匹配的Convert2JSValue重载！
        },
        value);
}
}
}
#endif  // INTERFACES_KITS_JS_RDB_INCLUDE_RESULT_SET_NAPI_H_