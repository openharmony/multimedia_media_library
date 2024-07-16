/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

export class AlbumPickerComponent extends ViewPU {
    constructor(e, o, n, t = -1, i = void 0) {
        super(e, n, t);
        'function' === typeof i && (this.paramsGenerator_ = i);
        this.albumPickerOptions = void 0;
        this.onAlbumClick = void 0;
        this.setInitiallyProvidedValue(o);
    }

    setInitiallyProvidedValue(e) {
        void 0 !== e.albumPickerOptions && (this.albumPickerOptions = e.albumPickerOptions);
        void 0 !== e.onAlbumClick && (this.onAlbumClick = e.onAlbumClick);
    }

    updateStateVars(e) {
    }

    purgeVariableDependenciesOnElmtId(e) {
    }

    aboutToBeDeleted() {
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal();
    }

    initialRender() {
        this.observeComponentCreation2(((e, o) => {
            Row.create();
            Row.height('100%');
        }), Row);
        this.observeComponentCreation2(((e, o) => {
            Column.create();
            Column.width('100%');
        }), Column);
        this.observeComponentCreation2(((e, o) => {
            var n;
            SecurityUIExtensionComponent.create({
                parameters: {
                    'ability.want.params.uiExtensionTargetType': 'photoPicker',
                    targetPage: 'albumPage',
                    themeColorMode: null === (n = this.albumPickerOptions) || void 0 === n ? void 0 : n.themeColorMode
                }
            });
            SecurityUIExtensionComponent.height('100%');
            SecurityUIExtensionComponent.width('100%');
            SecurityUIExtensionComponent.onRemoteReady((e => {
                console.info('AlbumPickerComponent onRemoteReady');
            }));
            SecurityUIExtensionComponent.onReceive((e => {
                let o = e;
                let n = o.dataType;
                if ('selectAlbum' === n && this.onAlbumClick) {
                    let e = new AlbumInfo;
                    e.uri = o.albumUri;
                    this.onAlbumClick(e);
                }
                console.info('AlbumPickerComponent onReceive ' + n);
            }));
            SecurityUIExtensionComponent.onError((() => {
                console.info('AlbumPickerComponent onError');
            }));
        }), SecurityUIExtensionComponent);
        Column.pop();
        Row.pop();
    }

    rerender() {
        this.updateDirtyElements();
    }
}

export class AlbumPickerOptions {
}

export class AlbumInfo {
}

export default { AlbumPickerComponent, AlbumPickerOptions, AlbumInfo };