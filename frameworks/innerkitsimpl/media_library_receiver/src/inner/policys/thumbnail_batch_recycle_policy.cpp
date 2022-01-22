/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "inner/policys/thumbnail_batch_recycle_policy.h"
#include <cstdio>
#include "media_log.h"
namespace OHOS {
namespace Media {
namespace {
static const std::string CLASS_NAME = "ThumbnailBatchRecyclePolicy";
}
void ThumbnailBatchRecyclePolicy::OnEvent(const sptr<ExecuteEvent> &executeEvent)
{
    printf("ThumbnailBatchRecyclePolicy::OnEvent ******[%s]=[%d]*********\n",
        executeEvent->event.c_str(), executeEvent->GetID());
}

const std::string ThumbnailBatchRecyclePolicy::GetClassName() const
{
    return CLASS_NAME;
}

void ThumbnailBatchRecyclePolicy::Dump() const
{
    printf("ThumbnailBatchRecyclePolicy::Dump ***************\n");
}
} // namespace Media
} // namespace OHOS