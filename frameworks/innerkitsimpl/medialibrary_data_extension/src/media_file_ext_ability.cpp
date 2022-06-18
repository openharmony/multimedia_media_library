/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "media_file_ext_ability.h"

#include "media_lib_service_const.h"
#include "extension_context.h"
#include "file_ext_stub_impl.h"
#include "ability_info.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "media_file_extention_utils.h"

namespace OHOS {
namespace Media {
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::FileAccessFwk;

MediaFileExtAbility::MediaFileExtAbility(JsRuntime& jsRuntime) : jsRuntime_(jsRuntime) {}

MediaFileExtAbility::~MediaFileExtAbility()
{
}

MediaFileExtAbility* MediaFileExtAbility::Create(const std::unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("create MediaFileExtAbility");
    return new MediaFileExtAbility(static_cast<JsRuntime&>(*runtime));
}

static MediaFileExtAbility* MediaFileExtCreator(const std::unique_ptr<Runtime>& runtime)
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    return  MediaFileExtAbility::Create(runtime);
}

__attribute__((constructor)) void RegisterFileExtCreator()
{
    MEDIA_INFO_LOG("MediaFileExtCreator::%s", __func__);
    FileExtAbility::SetCreator(MediaFileExtCreator);
}

void MediaFileExtAbility::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    MEDIA_INFO_LOG("Init MediaFileExtAbility");
    FileExtAbility::Init(record, application, handler, token);
    auto context = GetContext();
    if (context == nullptr) {
        MEDIA_ERR_LOG("Failed to get context");
        return;
    }
    MEDIA_INFO_LOG("%{public}s runtime language  %{public}d", __func__, jsRuntime_.GetLanguage());
    MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context);
}

void MediaFileExtAbility::OnStart(const AAFwk::Want &want)
{
    MEDIA_INFO_LOG("Onstart MediaFileExtAbility");
    Extension::OnStart(want);
}

sptr<IRemoteObject> MediaFileExtAbility::OnConnect(const AAFwk::Want &want)
{
    MEDIA_DEBUG_LOG("OnConnect MediaFileExtAbility");
    Extension::OnConnect(want);
    sptr<FileExtStubImpl> remoteObject = new (std::nothrow) FileExtStubImpl(
        std::static_pointer_cast<MediaFileExtAbility>(shared_from_this()),
        reinterpret_cast<napi_env>(&jsRuntime_.GetNativeEngine()));
    if (remoteObject == nullptr) {
        MEDIA_ERR_LOG("OnConnect MediaFileExtAbility get obj fail");
        return nullptr;
    }

    return remoteObject->AsObject();
}

int MediaFileExtAbility::OpenFile(const Uri &uri, int flags)
{
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    string mode = "r";
    if (flags == 1) {
        mode = "w";
    } else if (flags > 1) {
        mode = "rw";
    }
    return MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
}

std::vector<FileAccessFwk::FileInfo> MediaFileExtAbility::ListFile(const Uri &selectUri)
{
    MEDIA_DEBUG_LOG("%{public}s begin.", __func__);
    std::vector<string> typeArray;
    auto ret = MediaFileExtentionUtils::ListFile(selectUri.ToString());
    MEDIA_DEBUG_LOG("%{public}s end.", __func__);
    return ret;
}
} // Media
} // OHOS
