/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include <string>

#include "bundle_mgr_interface.h"

namespace OHOS {
namespace Media {
const std::string PERMISSION_NAME_READ_MEDIA = "ohos.permission.READ_MEDIA";
const std::string PERMISSION_NAME_WRITE_MEDIA = "ohos.permission.WRITE_MEDIA";
const std::string FILE_USR_CREATED = ".nofile";

class PermissionUtils {
public:
    static bool CheckCallerPermission(const std::string &permission);
    static bool CheckCallerSpecialFilePerm(const std::string &displayName);

private:
    PermissionUtils() {};
    virtual ~PermissionUtils() {};

    static sptr<AppExecFwk::IBundleMgr> bundleMgr_;
    static std::mutex bundleMgrMutex_;
};
}  // namespace Media
}  // namespace OHOS
