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
#define MLOG_TAG "MediaLibraryHelperContainer"

#include "medialibrary_helper_container.h"

namespace OHOS {
namespace Media {
std::shared_ptr<MediaLibraryHelperContainer> MediaLibraryHelperContainer::instance_ = nullptr;
std::mutex MediaLibraryHelperContainer::mutex_;
std::shared_ptr<DataShare::DataShareHelper> MediaLibraryHelperContainer::dataShareHelper_ = nullptr;

std::shared_ptr<MediaLibraryHelperContainer> MediaLibraryHelperContainer::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<MediaLibraryHelperContainer>();
        }
    }
    return instance_;
}

void MediaLibraryHelperContainer::CreateDataShareHelper(const sptr<IRemoteObject> &token,
    const std::string &uri)
{
    if (dataShareHelper_ == nullptr) {
        dataShareHelper_ = DataShare::DataShareHelper::Creator(token, uri);
    }
}

void MediaLibraryHelperContainer::SetDataShareHelper(const std::shared_ptr<DataShare::DataShareHelper> &helper)
{
    dataShareHelper_ = helper;
}

std::shared_ptr<DataShare::DataShareHelper> MediaLibraryHelperContainer::GetDataShareHelper()
{
    return dataShareHelper_;
}
} // namespace Media
} // namespace OHOS
