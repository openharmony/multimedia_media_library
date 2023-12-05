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
#include "medialibrary_client_errno.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
DeleteCallback::DeleteCallback(napi_env env, Ace::UIContent *uiContent)
{
    this->env_ = env;
    this->uiContent = uiContent;
}

void DeleteCallback::OnRelease(int32_t releaseCode)
{
    NAPI_INFO_LOG("OnRelease enter. release code is %{public}d", releaseCode);
    CloseModalUIExtension();
}

void DeleteCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    NAPI_INFO_LOG("OnResult enter. resultCode is %{public}d", resultCode);
    this->resultCode_ = resultCode;
    if (resultCode == DELETE_CODE_SUCCESS) {
        string trashUri = PAH_TRASH_PHOTO;
        MediaLibraryNapiUtils::UriAppendKeyValue(trashUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri updateAssetUri(trashUri);
        DataSharePredicates predicates;
        predicates.In(MediaColumn::MEDIA_ID, this->uris_);
        DataShareValuesBucket valuesBucket;
        valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
        int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
        if (changedRows < 0) {
            NAPI_ERR_LOG("Media asset delete failed, err: %{public}d", changedRows);
            this->resultCode_ = DELETE_CODE_ERROR;
        }
        NAPI_ERR_LOG("Media asset delete end");
    }
    SendMessageBack();
}

void DeleteCallback::OnError(int32_t code, const string &name, const string &message)
{
    NAPI_ERR_LOG("OnError enter. errorCode=%{public}d, name=%{public}s, message=%{public}s",
                 code, name.c_str(), message.c_str());
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
    if (this->uiContent != nullptr) {
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
}
}
}