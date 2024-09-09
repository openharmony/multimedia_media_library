/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2024. All rights reserved.
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

#define MLOG_TAG "EnhancementServiceAdapter"

#include "enhancement_service_adapter.h"

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "media_enhance_client.h"
#include "media_enhance_bundle.h"
#endif

#include "ipc_skeleton.h"
#include "media_log.h"
#include "medialibrary_errno.h"

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "enhancement_service_callback.h"
#endif

using namespace std;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
using namespace OHOS::MediaEnhance;
#endif

namespace OHOS {
namespace Media {

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
int32_t EnhancementServiceAdapter::LoadEnhancementService()
{
    if (enhancementClient_ == nullptr) {
        MEDIA_WARN_LOG("EnhancementServiceAdapter get mediaEnhanceClient error, make client pointer again");
        enhancementClient_ = make_shared<MediaEnhanceClient>(TASK_TYPE::TYPE_CAMERA);
    }
    if (!enhancementClient_->IsConnected()) {
        int ret = enhancementClient_->LoadSA();
        if (ret != E_OK) {
            MEDIA_ERR_LOG("EnhancementServiceAdapter load enhancement service SA error");
            return ret;
        }
        sptr<EnhancementServiceCallback> callback = sptr<EnhancementServiceCallback>::MakeSptr();
        ret = enhancementClient_->SetResultCallback(callback);
        if (ret != E_OK) {
            MEDIA_ERR_LOG("EnhancementServiceAdapter set enhancement callback error");
            return ret;
        }
        MEDIA_INFO_LOG("EnhancementServiceAdapter load enhancement service SA");
    }
    return E_OK;
}
#endif

EnhancementServiceAdapter::EnhancementServiceAdapter()
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    enhancementClient_ = make_shared<MediaEnhanceClient>(TASK_TYPE::TYPE_CAMERA);
    LoadEnhancementService();
#endif
    MEDIA_INFO_LOG("EnhancementServiceAdapter init succ");
}

EnhancementServiceAdapter::~EnhancementServiceAdapter() {}

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
int32_t EnhancementServiceAdapter::AddTask(const string &taskId, MediaEnhanceBundle &enhanceBundle)
{
    int32_t triggerType = enhanceBundle.GetInt(MediaEnhanceBundleKey::TRIGGER_TYPE);
    MEDIA_INFO_LOG("add task: enter taskId: %{public}s, triggerType: %{public}d",
        taskId.c_str(), triggerType);
    int32_t ret = LoadEnhancementService();
    if (ret != E_OK) {
        return ret;
    }
    ret = enhancementClient_->AddTask(taskId, enhanceBundle);
    if (ret == E_OK) {
        CloudEnhancementGetCount::GetInstance().AddStartTime(taskId);
    }
    return ret;
}

int32_t EnhancementServiceAdapter::RemoveTask(const string &taskId)
{
    int32_t ret = LoadEnhancementService();
    if (ret != E_OK) {
        return ret;
    }
    return enhancementClient_->RemoveTask(taskId);
}

int32_t EnhancementServiceAdapter::CancelTask(const string &taskId)
{
    int32_t ret = LoadEnhancementService();
    if (ret != E_OK) {
        return ret;
    }
    return enhancementClient_->CancelTask(taskId);
}

int32_t EnhancementServiceAdapter::CancelAllTasks()
{
    int32_t ret = LoadEnhancementService();
    if (ret != E_OK) {
        return ret;
    }
    return enhancementClient_->StopService();
}

int32_t EnhancementServiceAdapter::GetPendingTasks(vector<string> &taskIdList)
{
    int32_t ret = LoadEnhancementService();
    if (ret != E_OK) {
        return ret;
    }
    return enhancementClient_->GetPendingTasks(taskIdList);
}
#endif
} // namespace Media
} // namespace OHOS