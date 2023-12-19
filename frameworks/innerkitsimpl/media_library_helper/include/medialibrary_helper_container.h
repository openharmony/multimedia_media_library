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

#ifndef FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIB_DATASHAREHELPER_CONTAINER_H_
#define FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIB_DATASHAREHELPER_CONTAINER_H_

#include "datashare_helper.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
/**
 * @brief Utility class for file operations
 *
 * @since 1.0
 * @version 1.0
 */
class MediaLibraryHelperContainer {
public:
    EXPORT MediaLibraryHelperContainer() = default;
    EXPORT virtual ~MediaLibraryHelperContainer() = default;

    EXPORT static std::shared_ptr<MediaLibraryHelperContainer> GetInstance();
    EXPORT void CreateDataShareHelper(const sptr<IRemoteObject> &token, const std::string &uri);
    EXPORT void SetDataShareHelper(const std::shared_ptr<DataShare::DataShareHelper> &helper);
    EXPORT std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper();

private:
    static std::mutex mutex_;
    static std::shared_ptr<MediaLibraryHelperContainer> instance_;
    static std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
};
} // namespace Media
} // namespace  OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_MEDIA_LIBRARY_INCLUDE_MEDIA_LIB_DATASHAREHELPER_CONTAINER_H_
