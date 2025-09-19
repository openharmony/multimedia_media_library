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

#include "cloud_media_download_resources_status_napi.h"

#include <fcntl.h>
#include <unistd.h>

#include "directory_ex.h"
#include "file_uri.h"
#include "media_file_utils.h"
#include "media_library_napi.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_utils.h"
#include "userfile_client.h"
#include "cloud_media_asset_types.h"

using namespace std;
namespace OHOS::Media {
static const string CLOUD_MEDIA_DOWNLOAD_RESOURCES_STATUS_NAPI = "CloudAssetsDownloadStatus";
thread_local napi_ref CloudMediaDownloadResourcesStatusNapi::constructor_ = nullptr;

napi_value CloudMediaDownloadResourcesStatusNapi::Init(napi_env env, napi_value exports)
{
    NapiClassInfo info = {
        .name = CLOUD_MEDIA_DOWNLOAD_RESOURCES_STATUS_NAPI,
        .ref = &constructor_,
        .constructor = Constructor,
        .props = {
            DECLARE_NAPI_GETTER("taskInfos", JSGetTaskInfos),
        }
    };
    MediaLibraryNapiUtils::NapiDefineClass(env, exports, info);
    return exports;
}

napi_value CloudMediaDownloadResourcesStatusNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value newTarget = nullptr;
    CHECK_ARGS(env, napi_get_new_target(env, info, &newTarget), JS_INNER_FAIL);
    CHECK_COND_RET(newTarget != nullptr, nullptr, "Invalid call to constructor");

    size_t argc = ARGS_ZERO;
    napi_value thisVar = nullptr;
    CHECK_ARGS(env, napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr), JS_INNER_FAIL);
    CHECK_COND_WITH_MESSAGE(env, argc == ARGS_ZERO, "Number of args is invalid");

    unique_ptr<CloudMediaDownloadResourcesStatusNapi> obj = make_unique<CloudMediaDownloadResourcesStatusNapi>();
    CHECK_ARGS(env,
        napi_wrap(env, thisVar, reinterpret_cast<void*>(obj.get()), CloudMediaDownloadResourcesStatusNapi::Destructor,
        nullptr, nullptr), JS_INNER_FAIL);
    obj.release();
    return thisVar;
}

void CloudMediaDownloadResourcesStatusNapi::Destructor(napi_env env, void* nativeObject, void* finalizeHint)
{
    auto* cloudMediaDownloadResourcesStatusNapi = reinterpret_cast<CloudMediaDownloadResourcesStatusNapi*>(
        nativeObject);
    if (cloudMediaDownloadResourcesStatusNapi == nullptr) {
        NAPI_ERR_LOG("cloudMediaDownloadResourcesStatusNapi is nullptr");
        return;
    }

    delete cloudMediaDownloadResourcesStatusNapi;
    cloudMediaDownloadResourcesStatusNapi = nullptr;
}

std::vector<std::string> CloudMediaDownloadResourcesStatusNapi::GetTaskInfos() const
{
    return this->taskInfos_;
}

void CloudMediaDownloadResourcesStatusNapi::SetTaskInfos(const std::vector<std::string>  &taskInfos)
{
    this->taskInfos_ = taskInfos;
}

napi_value CloudMediaDownloadResourcesStatusNapi::NewCloudMediaDownloadResourcesStatusNapi(napi_env env,
    CloudMediaAssetAsyncContext* context)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_status status = napi_get_reference_value(env, constructor_, &constructor);
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to get reference of constructor, napi status: %{public}d",
        static_cast<int>(status));
    status = napi_new_instance(env, constructor, 0, nullptr, &instance);
    CHECK_COND_RET(status == napi_ok, nullptr,
        "Failed to get new instance of cloud media asset manager task state, napi status: %{public}d",
        static_cast<int>(status));
    CHECK_COND_RET(instance != nullptr, nullptr, "Instance is nullptr");

    CloudMediaDownloadResourcesStatusNapi* cloudMediaDownloadResourcesStatusNapi = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void**>(&cloudMediaDownloadResourcesStatusNapi));
    CHECK_COND_RET(status == napi_ok, nullptr, "Failed to unwarp instance of CloudMediaDownloadResourcesStatusNapi");
    CHECK_COND_RET(cloudMediaDownloadResourcesStatusNapi != nullptr, nullptr,
        "cloudMediaDownloadResourcesStatusNapi is nullptr");
    cloudMediaDownloadResourcesStatusNapi->SetTaskInfos(context->allBatchDownloadStatus);
    return instance;
}

napi_value CloudMediaDownloadResourcesStatusNapi::JSGetTaskInfos(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value thisVar = nullptr;
    napi_value result = nullptr;
    CloudMediaDownloadResourcesStatusNapi* obj = nullptr;

    napi_get_undefined(env, &result);
    GET_JS_OBJ_WITH_ZERO_ARGS(env, info, status, thisVar);
    if (status != napi_ok || thisVar == nullptr) {
        NAPI_ERR_LOG("Invalid arguments! status: %{public}d", status);
        return result;
    }

    status = napi_unwrap(env, thisVar, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        NAPI_ERR_LOG("Failed to get taskInfo");
        return nullptr;
    }
    
    std::vector<std::string> taskInfos = obj->GetTaskInfos();
    napi_create_array_with_length(env, taskInfos.size(), &result);
    for (size_t i = 0; i < taskInfos.size(); i++) {
        napi_value outInfo = nullptr;
        napi_get_undefined(env, &outInfo);
        napi_create_string_utf8(env, taskInfos[i].c_str(), NAPI_AUTO_LENGTH, &outInfo);
        napi_set_element(env, result, i, outInfo);
    }
    return result;
}
}