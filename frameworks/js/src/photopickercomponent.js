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

var __decorate = this && this.__decorate || function (e, o, t, i) {
    var n, r = arguments.length, s = r < 3 ? o : null === i ? i = Object.getOwnPropertyDescriptor(o, t) : i;
    if ("object" === typeof Reflect && "function" === typeof Reflect.decorate) s = Reflect.decorate(e, o, t, i); else for (var l = e.length - 1;l >= 0; l--) (n = e[l]) && (s = (r < 3 ? n(s) : r > 3 ? n(o, t, s) : n(o, t)) || s);
    return r > 3 && s && Object.defineProperty(o, t, s), s
};
const photoAccessHelper = requireNapi('file.photoAccessHelper');
const FILTER_MEDIA_TYPE_ALL = "FILTER_MEDIA_TYPE_ALL";
const FILTER_MEDIA_TYPE_IMAGE = "FILTER_MEDIA_TYPE_IMAGE";
const FILTER_MEDIA_TYPE_VIDEO = "FILTER_MEDIA_TYPE_VIDEO";

export class PhotoPickerComponent extends ViewPU {
    constructor(e, o, t, i = -1, n = void 0) {
        super(e, t, i);
        "function" === typeof n && (this.paramsGenerator_ = n);
        this.pickerOptions = void 0;
        this.onSelect = void 0;
        this.onDeselect = void 0;
        this.__pickerController = new SynchedPropertyNesedObjectPU(o.pickerController, this, "pickerController");
        this.proxy = void 0;
        this.setInitiallyProvidedValue(o);
        this.declareWatch("pickerController", this.onChanged)
    }

    setInitiallyProvidedValue(e) {
        void 0 !== e.pickerOptions && (this.pickerOptions = e.pickerOptions);
        void 0 !== e.onSelect && (this.onSelect = e.onSelect);
        void 0 !== e.onDeselect && (this.onDeselect = e.onDeselect);
        this.__pickerController.set(e.pickerController);
        void 0 !== e.proxy && (this.proxy = e.proxy)
    }

    updateStateVars(e) {
        this.__pickerController.set(e.pickerController)
    }

    purgeVariableDependenciesOnElmtId(e) {
        this.__pickerController.purgeDependencyOnElmtId(e)
    }

    aboutToBeDeleted() {
        this.__pickerController.aboutToBeDeleted();
        SubscriberManager.Get().delete(this.id__());
        this.aboutToBeDeletedInternal()
    }

    get pickerController() {
        return this.__pickerController.get()
    }

    onChanged() {
        var e, o, t;
        console.info("PhotoPickerComponent onchanged" + (null === (o = null === (e = this.pickerController) || void 0 === e ? void 0 : e.selectedUris) || void 0 === o ? void 0 : o.toString));
        this.proxy && this.proxy.send({
            selectUris: null === (t = this.pickerController) || void 0 === t ? void 0 : t.selectedUris
        })
    }

    initialRender() {
        this.observeComponentCreation2(((e, o) => {
            Row.create();
            Row.height("100%")
        }), Row);
        this.observeComponentCreation2(((e, o) => {
            Column.create();
            Column.width("100%")
        }), Column);
        this.observeComponentCreation2(((e, o) => {
            var t, i, n, r, s, l;
            UIExtensionComponent.create({
                parameters: {
                    "ability.want.params.uiExtensionTargetType": "photoPicker",
                    uri: "multipleselect",
                    filterMediaType: this.convertMIMETypeToFilterType(null === (t = this.pickerOptions) || void 0 === t ? void 0 : t.MIMEType),
                    maxSelectNumber: null === (i = this.pickerOptions) || void 0 === i ? void 0 : i.maxSelectNumber,
                    isPhotoTakingSupported: null === (n = this.pickerOptions) || void 0 === n ? void 0 : n.isPhotoTakingSupported,
                    isEditSupported: !1,
                    recommendationOptions: null === (r = this.pickerOptions) || void 0 === r ? void 0 : r.recommendationOptions,
                    preselectedUri: null === (s = this.pickerOptions) || void 0 === s ? void 0 : s.preselectedUris,
                    isFromPickerView: !0,
                    isNeedActionBar: !1,
                    isNeedSelectBar: !1,
                    isSearchSupported: null === (l = this.pickerOptions) || void 0 === l ? void 0 : l.isSearchSupported
                }
            });
            UIExtensionComponent.height("100%");
            UIExtensionComponent.width("100%");
            UIExtensionComponent.onRemoteReady((e => {
                this.proxy = e
            }));
            UIExtensionComponent.onReceive((e => {
                let o = e;
                if ("selectOrDeselect" === o.dataType) {
                    o.isSelect ? this.onSelect && this.onSelect(o["select-item-list"]) : this.onDeselect && this.onDeselect(o["select-item-list"])
                } else console.info("PhotoPickerComponent onReceive: other case");
                console.info("PhotoPickerComponent onReceive" + JSON.stringify(o))
            }));
            UIExtensionComponent.onResult((e => {
                console.info("PhotoPickerComponent onResult")
            }));
            UIExtensionComponent.onError((() => {
                console.info("PhotoPickerComponent onError")
            }));
            UIExtensionComponent.onRelease((e => {
                console.info("PhotoPickerComponent onRelease")
            }))
        }), UIExtensionComponent);
        Column.pop();
        Row.pop()
    }

    convertMIMETypeToFilterType(e) {
        let o;
        o = e === photoAccessHelper.PhotoViewMIMETypes.IMAGE_TYPE ? FILTER_MEDIA_TYPE_IMAGE : e === photoAccessHelper.PhotoViewMIMETypes.VIDEO_TYPE ? FILTER_MEDIA_TYPE_VIDEO : FILTER_MEDIA_TYPE_ALL;
        console.info("PhotoPickerComponent convertMIMETypeToFilterType" + JSON.stringify(o));
        return o
    }

    rerender() {
        this.updateDirtyElements()
    }
}
let PickerController = class {
    setData(e, o) {
        if (o && e === DataType.SET_SELECTED_URIS && o instanceof Array) {
            let e = o;
            if (e) {
                this.selectedUris = [...e];
                console.info("PhotoPickerComponent setData" + JSON.stringify(this.selectedUris))
            }
        }
    }
};
PickerController = __decorate([Observed], PickerController);

export class PickerOptions extends photoAccessHelper.BaseSelectOptions {
}

export var DataType;
!function(e){
    e[e.SET_SELECTED_URIS=1] = "SET_SELECTED_URIS"
}(DataType || (DataType = {}));

export default { PhotoPickerComponent, PickerController, PickerOptions, DataType }