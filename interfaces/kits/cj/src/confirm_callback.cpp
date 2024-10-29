/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "confirm_callback.h"

#include "media_file_utils.h"
#include "userfile_client.h"

namespace OHOS {
namespace Media {
namespace {
static constexpr int32_t CONFIRM_CODE_SUCCESS = 0;
static constexpr int32_t CONFIRM_CODE_USER_DENY = -1;
static const std::string CONFIRM_BOX_DES_FILE_URIS = "desFileUris";
static const std::string RESULT_PARAM = "result";
static const std::string DATA_PARAM = "data";
}
#ifdef HAS_ACE_ENGINE_PART
ConfirmCallback::ConfirmCallback(Ace::UIContent *uiContent, int64_t funcId)
{
    this->uiContent = uiContent;
    this->funcId = funcId;
    this->retDataCArrString = {
        .data = { .head = nullptr, .size = 0 }
    };
}
#else
ConfirmCallback::ConfirmCallback(int64_t funcId)
{
    this->funcId = funcId;
    this->retDataCArrString = {
        .data = { .head = nullptr, .size = 0 }
    };
}
#endif
void ConfirmCallback::OnRelease(int32_t releaseCode)
{
    LOGI("ReleaseCode is %{public}d.", releaseCode);

    CloseModalUIExtension();
}

void ConfirmCallback::OnResult(int32_t resultCode, const OHOS::AAFwk::Want &want)
{
    LOGI("ResultCode is %{public}d.", resultCode);

    this->resultCode_ = resultCode;
    std::vector<std::string> desFileUris;
    if (resultCode == CONFIRM_CODE_SUCCESS) {
        // check if the desFileUris exsit
        if (!want.HasParameter(CONFIRM_BOX_DES_FILE_URIS)) {
            LOGE("Can't get string array from want.");
            this->resultCode_ = JS_INNER_FAIL;
            SendMessageBack(desFileUris);
            return;
        }

        // get desFileUris from want
        desFileUris = want.GetStringArrayParam(CONFIRM_BOX_DES_FILE_URIS);
    } else if (resultCode == CONFIRM_CODE_USER_DENY) {
        this->resultCode_ = CONFIRM_CODE_SUCCESS; // user deny return success with empty uris
    }

    SendMessageBack(desFileUris);
}

void ConfirmCallback::OnError(int32_t code, const std::string &name, const std::string &message)
{
    LOGI("Code is %{public}d, name is %{public}s, message is %{public}s.", code, name.c_str(),
        message.c_str());

    this->resultCode_ = JS_INNER_FAIL;
    std::vector<std::string> desFileUris;
    SendMessageBack(desFileUris);
}

void ConfirmCallback::OnReceive(const OHOS::AAFwk::WantParams &request)
{
    LOGI("ConfirmCallback Called.");
}

void ConfirmCallback::SetSessionId(int32_t sessionId)
{
    this->sessionId_ = sessionId;
}

void ConfirmCallback::SendMessageBack(const std::vector<std::string> &desFileUris)
{
    CloseModalUIExtension();
    this->retDataCArrString.code = this->resultCode_;
    size_t len = desFileUris.size();
    if (len > 0) {
        char** head = static_cast<char **>(malloc(sizeof(char *) * len));
        if (head == nullptr) {
            LOGE("SendMessageBack malloc desFileUris failed.");
            this->resultCode_ = JS_INNER_FAIL;
            return;
        }
        for (size_t i = 0; i < len; ++i) {
            head[i] = MallocCString(desFileUris[i]);
        }
        this->retDataCArrString.data.head = head;
        this->retDataCArrString.data.size = static_cast<int64_t>(len);
    }
    // callback
    auto func = reinterpret_cast<void(*)(RetDataCArrString)>(this->funcId);
    auto callbackRef = CJLambda::Create(func);
    if (callbackRef == nullptr) {
        LOGE("RegisterNotifyChange on register callback is nullptr.");
        this->resultCode_ = JS_INNER_FAIL;
    } else {
        callbackRef(this->retDataCArrString);
    }
    if (this->retDataCArrString.data.size > 0) {
        for (int64_t i = 0; i < this->retDataCArrString.data.size; i++) {
            free(this->retDataCArrString.data.head[i]);
            this->retDataCArrString.data.head[i] = nullptr;
        }
        free(this->retDataCArrString.data.head);
        this->retDataCArrString.data.head = nullptr;
        this->retDataCArrString.data.size = 0;
    }
}

void ConfirmCallback::CloseModalUIExtension()
{
    LOGI("Called.");

#ifdef HAS_ACE_ENGINE_PART
    if (this->uiContent != nullptr) {
        uiContent->CloseModalUIExtension(this->sessionId_);
    }
#endif
}
}
}