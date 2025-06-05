/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "delete_callback.h"

#include "media_library_napi.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_napi_log.h"
#include "media_file_utils.h"
#include "userfile_client.h"
#include "user_define_ipc_client.h"
#include "medialibrary_business_code.h"
#include "trash_photos_vo.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
#ifdef HAS_ACE_ENGINE_PART
DeleteCallback::DeleteCallback(napi_env env, Ace::UIContent *uiContent)
{
    this->env_ = env;
    this->uiContent = uiContent;
}
#else
DeleteCallback::DeleteCallback(napi_env env)
{
    this->env_ = env;
}
#endif

DeleteCallback::~DeleteCallback()
{
    napi_delete_reference(this->env_, this->callbackRef);
    this->env_ = nullptr;
    this->callbackRef = nullptr;
#ifdef HAS_ACE_ENGINE_PART
    this->uiContent = nullptr;
#endif
}

void DeleteCallback::OnRelease(int32_t releaseCode)
{
    CloseModalUIExtension();
}

void DeleteCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    if (resultCode == DELETE_CODE_SUCCESS) {
        this->resultCode_ = resultCode;
        TrashPhotosReqBody reqBody;
        reqBody.uris = this->uris_;
        uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_TRASH_PHOTOS);
        int32_t changedRows = IPC::UserDefineIPCClient().Call(businessCode, reqBody);
        if (changedRows < 0) {
            this->resultCode_ = JS_INNER_FAIL;
        }
    } else {
        this->resultCode_ = JS_ERR_PERMISSION_DENIED;
    }
    SendMessageBack();
}

void DeleteCallback::OnError(int32_t code, const string &name, const string &message)
{
    this->resultCode_ = JS_INNER_FAIL;
    SendMessageBack();
}

void DeleteCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    NAPI_INFO_LOG("OnReceive enter.");
}

void DeleteCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void DeleteCallback::SetUris(vector<string> uris)
{
    this->uris_.assign(uris.begin(), uris.end());
}

void DeleteCallback::SetFunc(napi_value func)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(this->env_, func, &valueType);
    if (valueType == napi_function) {
        napi_create_reference(this->env_, func, ARGS_ONE, &this->callbackRef);
    }
}

void DeleteCallback::SendMessageBack()
{
    CloseModalUIExtension();
    napi_value undefined;
    CHECK_ARGS_RET_VOID(this->env_, napi_get_undefined(this->env_, &undefined), JS_ERR_PARAMETER_INVALID);

    napi_value results[ARGS_ONE] = {nullptr};
    CHECK_ARGS_RET_VOID(this->env_, napi_create_object(this->env_, &results[PARAM0]), JS_ERR_PARAMETER_INVALID);

    napi_value result = 0;
    CHECK_ARGS_RET_VOID(this->env_, napi_create_int32(this->env_, this->resultCode_, &result),
                        JS_ERR_PARAMETER_INVALID);
    CHECK_ARGS_RET_VOID(this->env_, napi_set_named_property(this->env_, results[PARAM0], RESULT.c_str(), result),
                        JS_ERR_PARAMETER_INVALID);

    napi_value callback = nullptr;
    CHECK_ARGS_RET_VOID(this->env_, napi_get_reference_value(this->env_, this->callbackRef, &callback),
                        JS_ERR_PARAMETER_INVALID);
    napi_value returnVal;
    CHECK_ARGS_RET_VOID(this->env_, napi_call_function(this->env_, undefined, callback, ARGS_ONE, results, &returnVal),
                        JS_ERR_PARAMETER_INVALID);
}

void DeleteCallback::CloseModalUIExtension()
{
#ifdef HAS_ACE_ENGINE_PART
    if (this->uiContent != nullptr) {
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
#endif
}
}
}