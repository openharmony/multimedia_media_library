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

#include <ani.h>
#include <iostream>
#include <array>
#include "ani_error.h"
#include "ani_class_name.h"
#include "media_assets_change_request_ani.h"
#include "media_log.h"
#include "userfile_client.h"
#include "medialibrary_ani_log.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS::Media {

constexpr int32_t YES = 1;
constexpr int32_t NO = 0;

std::vector<std::shared_ptr<FileAsset>> MediaAssetsChangeRequestAni::fileAssets_;
std::vector<AssetsChangeOperation> MediaAssetsChangeRequestAni::assetsChangeOperations_;
bool MediaAssetsChangeRequestAni::isFavorite_;
bool MediaAssetsChangeRequestAni::isHidden_;

MediaAssetsChangeRequestAni::MediaAssetsChangeRequestAni(vector<shared_ptr<FileAsset>> fileAssets)
{
    fileAssets_ = fileAssets;
}

MediaAssetsChangeRequestAni::~MediaAssetsChangeRequestAni()
{
    assetsChangeOperations_.clear();
    fileAssets_.clear();
}

void MediaAssetsChangeRequestAni::RecordChangeOperation(AssetsChangeOperation changeOperation)
{
    assetsChangeOperations_.push_back(changeOperation);
}

void MediaAssetsChangeRequestAni::SetFavorite([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_boolean isFavorite)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }
    auto context =  unwrapp(env, object);
    if (context == nullptr) {
        return;
    }
    for (const auto& fileAsset : context->fileAssets_) {
        fileAsset->SetFavorite(isFavorite);
    }
    RecordChangeOperation(AssetsChangeOperation::BATCH_SET_FAVORITE);
}

void MediaAssetsChangeRequestAni::SetHidden([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_boolean isHidden)
{
    if (!MediaLibraryAniUtils::IsSystemApp()) {
        AniError::ThrowError(env, E_CHECK_SYSTEMAPP_FAIL, "This interface can be called only by system apps");
        return;
    }
    auto context = unwrapp(env, object);
    if (context == nullptr) {
        return;
    }
    for (const auto& fileAsset : context->fileAssets_) {
        fileAsset->SetHidden(isHidden);
    }
    RecordChangeOperation(AssetsChangeOperation::BATCH_SET_HIDDEN);
}

bool MediaAssetsChangeRequestAni::SetAssetsPropertyExecute(const AssetsChangeOperation& changeOperation)
{
    string uri;
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    predicates.In(PhotoColumn::MEDIA_ID, GetFileAssetUriArray());
    switch (changeOperation) {
        case AssetsChangeOperation::BATCH_SET_FAVORITE:
            uri = PAH_BATCH_UPDATE_FAVORITE;
            valuesBucket.Put(PhotoColumn::MEDIA_IS_FAV, GetFavoriteStatus() ? YES : NO);
            MEDIA_INFO_LOG("Batch set favorite: %{public}d", GetFavoriteStatus() ? YES : NO);
            break;
        case AssetsChangeOperation::BATCH_SET_HIDDEN:
            uri = PAH_HIDE_PHOTOS;
            valuesBucket.Put(PhotoColumn::MEDIA_HIDDEN, GetHiddenStatus() ? YES : NO);
            break;
        default:
            MEDIA_ERR_LOG("Unsupported assets change operation: %{public}d", changeOperation);
            return false;
    }

    MEDIA_INFO_LOG("changeOperation:%{public}d, size:%{public}zu",
        changeOperation, GetFileAssetUriArray().size());
    MediaLibraryAniUtils::UriAppendKeyValue(uri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri updateAssetsUri(uri);
    int32_t changedRows = UserFileClient::Update(updateAssetsUri, predicates, valuesBucket);
    if (changedRows < 0) {
        MEDIA_ERR_LOG("Failed to set property, operation: %{public}d, err: %{public}d", changeOperation, changedRows);
        return false;
    }
    return true;
}

ani_status MediaAssetsChangeRequestAni::ApplyChanges(ani_env *env, ani_object aniObject)
{
    auto context =  unwrapp(env, aniObject);
    if (context == nullptr) {
        return ANI_ERROR;
    }
    ANI_CHECK_RETURN_RET_LOG(context->assetsChangeOperations_.empty() == false, ANI_ERROR,
        "MediaAssetsChangeRequestAni::ApplyChanges assetsChangeOperations_ is empty");
    ANI_CHECK_RETURN_RET_LOG(context->fileAssets_.empty() == false, ANI_ERROR,
        "MediaAssetsChangeRequestAni::ApplyChanges fileAssets_ is empty");
    for (const auto& fileAsset : context->fileAssets_) {
        ANI_CHECK_RETURN_RET_LOG(fileAsset != nullptr && fileAsset->GetId() > 0 && fileAsset->GetUri().empty() == false,
            ANI_ERROR, "MediaAssetsChangeRequestAni::ApplyChanges check fileAssets_ failed");
    }

    unordered_set<AssetsChangeOperation> appliedOperations;
    for (const auto& changeOperation : assetsChangeOperations_) {
        // Keep the final result(s) of each operation, and commit only once.
        if (appliedOperations.find(changeOperation) != appliedOperations.end()) {
            continue;
        }

        bool valid = MediaAssetsChangeRequestAni::SetAssetsPropertyExecute(changeOperation);
        if (!valid) {
            MEDIA_ERR_LOG("Failed to apply assets change request, operation: %{public}d", changeOperation);
            return ANI_ERROR;
        }
        appliedOperations.insert(changeOperation);
    }
    return ANI_OK;
}

vector<string> MediaAssetsChangeRequestAni::GetFileAssetUriArray()
{
    vector<string> uriArray;
    uriArray.reserve(fileAssets_.size());
    for (const auto& fileAsset : fileAssets_) {
        uriArray.push_back(fileAsset->GetUri());
    }
    return uriArray;
}

bool MediaAssetsChangeRequestAni::GetFavoriteStatus()
{
    return isFavorite_;
}

bool MediaAssetsChangeRequestAni::GetHiddenStatus()
{
    return isHidden_;
}


MediaAssetsChangeRequestAni* MediaAssetsChangeRequestAni::unwrapp(ani_env *env, ani_object object)
{
    ani_long context;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeMediaAssetsChangeRequestHandleImpl", &context)) {
        ANI_ERR_LOG("unwrapp err");
        return nullptr;
    }
    return reinterpret_cast<MediaAssetsChangeRequestAni *>(context);
}

ani_object MediaAssetsChangeRequestAni::create([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class clazz)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    vector<shared_ptr<FileAsset>> fileAssets = {fileAsset};
    auto nativeMediaAssetsChangeRequestHandle = std::make_unique<MediaAssetsChangeRequestAni>(fileAssets);

    ani_class cls;
    if (ANI_OK != env->FindClass(ANI_CLASS_MEDIA_ASSETS_CHANGE_REQUEST.c_str(), &cls)) {
        ANI_ERR_LOG("Failed to find class: %s", ANI_CLASS_MEDIA_ASSETS_CHANGE_REQUEST.c_str());
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find MediaAssetsChangeRequest constructor method");
        return nullptr;
    }

    ani_object context_object;
    if (ANI_OK != env->Object_New(cls, ctor, &context_object,
        reinterpret_cast<ani_long>(nativeMediaAssetsChangeRequestHandle.get()))) {
        ANI_ERR_LOG("Failed to create MediaAssetsChangeRequest object");
        return nullptr;
    }

    nativeMediaAssetsChangeRequestHandle.release();
    return context_object;
}

ani_status MediaAssetsChangeRequestAni::MediaAssetsChangeRequestAniInit(ani_env *env)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(ANI_CLASS_MEDIA_ASSETS_CHANGE_REQUEST.c_str(), &cls)) {
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"SetFavoriteSync", nullptr,
            reinterpret_cast<void *>(MediaAssetsChangeRequestAni::SetFavorite)},
        ani_native_function {"SetHiddenSync",
            nullptr, reinterpret_cast<void *>(MediaAssetsChangeRequestAni::SetHidden)},
        ani_native_function {"create", nullptr, reinterpret_cast<void *>(MediaAssetsChangeRequestAni::create)},

    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        return ANI_ERROR;
    };

    return ANI_OK;
}
} // namespace OHOS::MEDIA