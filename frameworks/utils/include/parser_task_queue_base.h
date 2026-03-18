/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIALIBRARY_PARSER_TASK_QUEUE_BASE_H
#define OHOS_MEDIALIBRARY_PARSER_TASK_QUEUE_BASE_H

#include <queue>
#include <mutex>
#include <string>


namespace OHOS {
namespace Media {
constexpr size_t DEFAULT_MAX_TASK_NUM = 100;

class ParserTaskQueueBase {
public:
    virtual ~ParserTaskQueueBase() = default;
    bool AddTask(const std::string &path, const std::string &fileUri);

protected:
    virtual void ProcessTask(const std::pair<std::string, std::string> &task) = 0;
    virtual size_t GetMaxTaskNum() const;
    void SendUpdateNotify(const std::string &fileUri);

private:
    void StartTask();
    void ProcessTasks();
    std::pair<std::string, std::string> GetNextTask();
    std::queue<std::pair<std::string, std::string>> tasks_;
    std::mutex mtx_;
    bool processing_ = false;
};
} // namespace Media
} // namespace OHOS
#endif // OHOS_MEDIALIBRARY_PARSER_TASK_QUEUE_BASE_H
