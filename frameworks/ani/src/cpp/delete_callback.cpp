/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "medialibrary_ani_utils.h"
#include "media_file_utils.h"
#include "userfile_client.h"

namespace OHOS {
namespace Media {
#ifdef HAS_ACE_ENGINE_PART
DeleteCallback::DeleteCallback(ani_env *env, Ace::UIContent *uiContent)
{
    this->env_ = env;
    this->uiContent = uiContent;
}
#else
DeleteCallback::DeleteCallback(ani_env *env)
{
    this->env_ = env;
}
#endif

void DeleteCallback::OnRelease(int32_t releaseCode)
{
    CloseModalUIExtension();
}

void DeleteCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &result)
{
    if (resultCode == DELETE_CODE_SUCCESS) {
        this->resultCode_ = resultCode;
        string trashUri = PAH_TRASH_PHOTO;
        MediaLibraryAniUtils::UriAppendKeyValue(trashUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
        Uri updateAssetUri(trashUri);
        DataShare::DataSharePredicates predicates;
        predicates.In(MediaColumn::MEDIA_ID, this->uris_);
        DataShare::DataShareValuesBucket valuesBucket;
        valuesBucket.Put(MediaColumn::MEDIA_DATE_TRASHED, MediaFileUtils::UTCTimeSeconds());
        int32_t changedRows = UserFileClient::Update(updateAssetUri, predicates, valuesBucket);
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
    ANI_INFO_LOG("OnReceive enter.");
}

void DeleteCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void DeleteCallback::SetUris(vector<string> uris)
{
    this->uris_.assign(uris.begin(), uris.end());
}

void DeleteCallback::SetFunc(ani_object func)
{
    env_->GlobalReference_Create(static_cast<ani_ref>(func), &this->callbackRef);
}

void DeleteCallback::SendMessageBack()
{
    CloseModalUIExtension();
    ani_ref undefined;
    CHECK_NULL_PTR_RETURN_VOID(this->env_, "env_ is nullptr");
    CHECK_ARGS_RET_VOID(this->env_, this->env_->GetUndefined(&undefined), JS_ERR_PARAMETER_INVALID);
}

void DeleteCallback::CloseModalUIExtension()
{
#ifdef HAS_ACE_ENGINE_PART
    if (this->uiContent != nullptr) {
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
#endif
}
} // namespace Media
} // namespace OHOS
