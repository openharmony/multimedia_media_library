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
#ifndef OHOS_MEDIALIBRARY_INOTIFY_H
#define OHOS_MEDIALIBRARY_INOTIFY_H

#include <sys/inotify.h>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
struct WatchInfo {
    WatchInfo(const std::string &path, const std::string &uri, const std::string &bundleName,
        MediaLibraryApi api): path_(path), uri_(uri), bundleName_(bundleName), api_(api), meetEvent_(0){};
    std::string path_;
    std::string uri_;
    std::string bundleName_;
    MediaLibraryApi api_;
    int32_t meetEvent_;
};

class MediaLibraryInotify {
public:
    EXPORT static std::shared_ptr<MediaLibraryInotify> GetInstance();
    EXPORT int32_t AddWatchList(const std::string &path, const std::string &uri,
        MediaLibraryApi api = MediaLibraryApi::API_OLD);
    EXPORT MediaLibraryInotify() = default;
    EXPORT ~MediaLibraryInotify() = default;
    EXPORT int32_t RemoveByFileUri(const std::string &uri, MediaLibraryApi api = MediaLibraryApi::API_OLD);
    EXPORT void DoAging();
    void DoStop();
private:
    int32_t Remove(int wd);
    void WatchCallBack();
    int32_t Init();
    static std::shared_ptr<MediaLibraryInotify> instance_;
    static std::mutex mutex_;
    static inline std::unordered_map<int, struct WatchInfo> watchList_;
    static inline int inotifyFd_ = 0;
    static inline std::atomic<bool> isWatching_ = false;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_INOTIFY_H