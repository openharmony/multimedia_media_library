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
#ifndef FRAMEWORKS_SERVICES_MEDIA_FILE_EXTENTION_ABILITY_H_
#define FRAMEWORKS_SERVICES_MEDIA_FILE_EXTENTION_ABILITY_H_

#include "file_access_ext_ability.h"
#include "file_filter.h"
#include "js_runtime.h"

namespace OHOS {
namespace Media {
class MediaFileExtAbility : public FileAccessFwk::FileAccessExtAbility {
public:
    MediaFileExtAbility(AbilityRuntime::JsRuntime& jsRuntime);
    ~MediaFileExtAbility() override;
    static MediaFileExtAbility* Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;
    void OnStart(const AAFwk::Want &want) override;
    void OnStop() override;
    sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    int OpenFile(const Uri &uri, const int flags, int &fd) override;
    int CreateFile(const Uri &parentUri, const std::string &displayName,  Uri &newFileUri) override;
    int Mkdir(const Uri &parentUri, const std::string &displayName, Uri &newFileUri) override;
    int Delete(const Uri &sourceFileUri) override;
    int ListFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList) override;
    int ScanFile(const FileAccessFwk::FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
        const DistributedFS::FileFilter &filter, std::vector<FileAccessFwk::FileInfo> &fileList) override;
    int GetRoots(std::vector<FileAccessFwk::RootInfo> &rootList) override;
    int Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri) override;
    int Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri) override;
    int Access(const Uri &uri, bool &isExist) override;
private:
     AbilityRuntime::JsRuntime& jsRuntime_;
};
} // Media
} // OHOS
#endif // FRAMEWORKS_SERVICES_MEDIA_FILE_EXTENTION_ABILITY_H_
