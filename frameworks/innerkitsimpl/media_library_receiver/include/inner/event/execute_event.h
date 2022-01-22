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
#ifndef EXECUTE_EVENT_H
#define EXECUTE_EVENT_H
#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <refbase.h>
namespace OHOS {
namespace Media {
struct ExecuteEvent : public RefBase {
public:
    const std::string event;
public:
    explicit ExecuteEvent(const std::string &e);
    ~ExecuteEvent();
public:
    bool IsCanceled() const;
    void Cancel();
    void Dump() const;
public:
    virtual uint32_t GetID(void) const final;
private:
    static uint32_t CreateID();
private:
    uint32_t id_ {0};
    uint64_t createTick_ {0};
    bool canceled_ {false};
private:
    static std::mutex staticMutex_;
    static uint32_t statcIndex_;
};
} // namespace Media
} // namespace OHOS
#endif // EXECUTE_EVENT_H
