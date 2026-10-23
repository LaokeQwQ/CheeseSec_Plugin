import { normalizeCatalog, filterCatalog } from "/catalog.mjs";

const copy = {
  zh: {
    skip: "跳到插件目录", store: "插件商店", explore: "发现插件", docs: "文档", serviceStatus: "服务状态",
    heroTitle: "为每一种防护，\n找到合适的扩展。", heroDescription: "面向 CheeseSec 全生态的独立插件，在不同产品间扩展你的安全工具。",
    learnPlugins: "了解 CheeseSec 插件", categories: "分类", categoryAll: "全部插件", categorySecurity: "检测与防护", categoryIntelligence: "威胁情报", categoryNotifications: "通知与集成", categoryAnalysis: "分析与审计", categoryTools: "开发工具",
    sidebarNote: "有一个好想法？\n从开发你的第一个插件开始。", developerGuide: "开发指南", sortLabel: "排序方式", sortNewest: "最近发布", sortName: "名称排序", catalogCaption: "适合你的下一份能力",
    loadingTitle: "正在查看插件目录", loadingDescription: "稍等片刻，新的能力正在加载。", emptyTitle: "暂无已发布插件", emptyDescription: "第一批插件正在准备中。你可以先了解插件的使用方式，或开始开发自己的扩展。",
    noResultsTitle: "没有找到匹配的插件", noResultsDescription: "换一个关键词，或清除筛选看看其他插件。", errorTitle: "暂时无法读取插件目录", errorDescription: "请检查网络连接，然后重新加载。", retry: "重新加载", resetFilters: "清除筛选",
    gettingStarted: "从这里开始", guideTitle: "认识插件，找到更多可能", guideDescription: "使用说明、发布方式与安全边界，一处读懂。", buildTogether: "和我们一起创造", buildTitle: "把你的想法，变成一个插件", buildDescription: "阅读开发指南，从一个清晰的小能力开始。",
    footerNote: "让安全的能力，触手可及。", catalogApi: "目录 API", detailNote: "请在插件说明中确认适用的 CheeseSec 产品、兼容版本与安装方式。", viewDocs: "查看使用文档",
    searchPlaceholder: "搜索插件名称或发布者", searchLabel: "搜索插件", clearSearch: "清除搜索", themeLight: "切换浅色模式", themeDark: "切换深色模式", closeDialog: "关闭详情", homeLabel: "CheeseSec 首页", navigation: "主导航", detailsLabel: "查看插件详情", version: "版本", publisher: "发布者", packageSize: "资源大小", releaseSequence: "发布序号", digest: "SHA-256 摘要",
    planned: "规划中", plannedNote: "规划中的扩展包只发布描述符，由宿主实现，当前不可安装。", notInstallable: "暂不可安装", extensionType: "扩展类型", planStatus: "状态", descriptorDigest: "描述符 SHA-256", descriptorReference: "描述符地址", extensionNotifier: "通知提供商", extensionStorage: "存储提供商", extensionDescriptor: "扩展描述符", extensionCloud: "云连接器", extensionObservability: "可观测性接入",
    trustOfficial: "官方", trustEnterprise: "企业", trustCommunity: "社区", trustPersonal: "个人", trustTest: "测试", trustDevelopment: "开发",
    lifecycleDescription: "生命周期示例，不提供防护能力。", lifecycleDetails: "这个示例仅用于验证启动、健康检查和停止流程，不检测攻击，也不采集数据。", compatibility: "适用平台", platformLinux: "仅支持 Linux amd64。", platformMac: "仅支持 macOS arm64（Apple 芯片）。", downloadPackage: "下载 .crp 包", verificationGuide: "签名校验说明", compatibilityGuide: "兼容性与安装说明",
  },
  en: {
    skip: "Skip to plugin catalog", store: "Plugin store", explore: "Explore", docs: "Documentation", serviceStatus: "Service status",
    heroTitle: "A little more power.\nA whole new possibility.", heroDescription: "Independent plugins for the CheeseSec ecosystem. Extend your security tools across products.",
    learnPlugins: "Meet CheeseSec plugins", categories: "CATEGORIES", categoryAll: "All plugins", categorySecurity: "Detection & protection", categoryIntelligence: "Threat intelligence", categoryNotifications: "Notifications & integrations", categoryAnalysis: "Analysis & audit", categoryTools: "Developer tools",
    sidebarNote: "Have an idea?\nStart with your first plugin.", developerGuide: "Developer guide", sortLabel: "Sort plugins", sortNewest: "Latest releases", sortName: "Name, A–Z", catalogCaption: "Find your next capability",
    loadingTitle: "Opening the plugin catalog", loadingDescription: "Just a moment. More possibilities are on their way.", emptyTitle: "The first plugins are on their way", emptyDescription: "There are no published plugins yet. Explore how plugins work, or start creating an extension of your own.",
    noResultsTitle: "No matching plugins", noResultsDescription: "Try another search, or clear your filters to see more plugins.", errorTitle: "The catalog could not be loaded", errorDescription: "Check your connection, then try loading it again.", retry: "Try again", resetFilters: "Clear filters",
    gettingStarted: "A GOOD PLACE TO START", guideTitle: "Get to know plugins", guideDescription: "Learn how plugins work, how they are released, and how to use them safely.", buildTogether: "LET’S BUILD SOMETHING", buildTitle: "Make your idea a plugin", buildDescription: "Open the developer guide. Start with one useful capability.",
    footerNote: "More possibilities. The same care for security.", catalogApi: "Catalog API", detailNote: "Check the plugin documentation for supported CheeseSec products, compatible versions, and installation steps.", viewDocs: "Read the documentation",
    searchPlaceholder: "Search plugin names or publishers", searchLabel: "Search plugins", clearSearch: "Clear search", themeLight: "Use light theme", themeDark: "Use dark theme", closeDialog: "Close plugin details", homeLabel: "CheeseSec home", navigation: "Main navigation", detailsLabel: "View plugin details", version: "Version", publisher: "Publisher", packageSize: "Package size", releaseSequence: "Release sequence", digest: "SHA-256 digest",
    planned: "Planned", plannedNote: "This planned pack publishes a descriptor only. It is implemented by the host and cannot be installed yet.", notInstallable: "Not installable yet", extensionType: "Extension type", planStatus: "Status", descriptorDigest: "Descriptor SHA-256", descriptorReference: "Descriptor URL", extensionNotifier: "Notifier provider", extensionStorage: "Storage provider", extensionDescriptor: "Extension descriptor", extensionCloud: "Cloud connector", extensionObservability: "Observability integration",
    trustOfficial: "Official", trustEnterprise: "Enterprise", trustCommunity: "Community", trustPersonal: "Personal", trustTest: "Test", trustDevelopment: "Development",
    lifecycleDescription: "Lifecycle example. No protection capabilities.", lifecycleDetails: "This example only checks startup, health, and shutdown. It does not detect attacks or collect data.", compatibility: "Supported platform", platformLinux: "Linux amd64 only.", platformMac: "macOS arm64 (Apple silicon) only.", downloadPackage: "Download .crp package", verificationGuide: "Signature verification", compatibilityGuide: "Compatibility & installation",
  },
};

const BRAND_ICONS = {
  "notifier-dingtalk": "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1024 1024\" width=\"2500\" height=\"2500\"><path fill=\"#4285F4\" d=\"M1024 155.733C1024 70.4 953.6 0 868.267 0H155.733C70.4 0 0 70.4 0 155.733v712.534C0 953.6 70.4 1024 155.733 1024h712.534C953.6 1024 1024 953.6 1024 868.267V155.733z\"/><path fill=\"#FFF\" d=\"M810.667 422.4c-2.134 6.4-4.267 14.933-8.534 23.467C774.4 505.6 701.867 620.8 701.867 620.8l-21.334 36.267h102.4L588.8 915.2l44.8-174.933h-78.933l27.733-115.2c-23.467 6.4-49.067 12.8-81.067 23.466 0 0-42.666 25.6-121.6-46.933 0 0-53.333-46.933-23.466-59.733 12.8-4.267 64-10.667 104.533-17.067 55.467-6.4 87.467-10.667 87.467-10.667s-168.534 2.134-206.934-4.266c-40.533-6.4-89.6-72.534-100.266-132.267 0 0-17.067-32 36.266-17.067s268.8 59.734 268.8 59.734-281.6-87.467-300.8-108.8c-19.2-21.334-55.466-115.2-51.2-172.8 0 0 2.134-14.934 17.067-10.667 0 0 209.067 96 352 147.2 140.8 53.333 264.533 81.067 247.467 147.2z\"/></svg>",
  "notifier-feishu": "<svg width=\"24\"\n     height=\"24\"\n     viewBox=\"0 0 24 24\"\n     fill=\"none\"\n     xmlns=\"http://www.w3.org/2000/svg\">\n  <path d=\"M12.9238 12.8029C12.9427 12.784 12.9616 12.7682 12.9806 12.7493C13.0184 12.7146 13.0563 12.6767 13.091 12.6389L13.1667 12.5631L13.397 12.336L14.7315 11.0173L15.0659 10.686C15.129 10.6229 15.1952 10.563 15.2615 10.5031C15.3845 10.3926 15.5076 10.2854 15.6369 10.1813C15.7536 10.0866 15.8767 9.99514 15.9997 9.9068C16.1732 9.78376 16.3499 9.67019 16.5329 9.55977C16.7127 9.45251 16.8957 9.35471 17.085 9.26322C17.2616 9.17804 17.4415 9.09917 17.6276 9.02661C17.7317 8.9856 17.8326 8.94774 17.9399 8.91304C17.9935 8.89411 18.044 8.87834 18.0977 8.86256C17.6276 7.00439 16.7632 5.3008 15.5991 3.84959C15.3719 3.56566 15.0249 3.40161 14.6589 3.40161H5.0084C4.83489 3.40161 4.76233 3.6256 4.90114 3.72656C8.18528 6.13997 10.9236 9.24114 12.9017 12.825C12.908 12.8187 12.9175 12.8124 12.9238 12.8029Z\"\n        fill=\"#00D6B9\" />\n  <path d=\"M9.09696 21.2986C14.0815 21.2986 18.4225 18.5476 20.6877 14.4843C20.7666 14.3423 20.8454 14.1972 20.918 14.052C20.8044 14.2729 20.6751 14.4811 20.5394 14.6767C20.4889 14.7461 20.4385 14.8155 20.388 14.8818C20.3217 14.9669 20.2555 15.049 20.1861 15.1278C20.1324 15.1909 20.0757 15.2509 20.0189 15.3108C19.9021 15.4307 19.7823 15.5474 19.6561 15.6547C19.5867 15.7146 19.5141 15.7714 19.4415 15.8282C19.3564 15.8944 19.268 15.9575 19.1797 16.0143C19.1229 16.0522 19.0661 16.09 19.0093 16.1247C18.9494 16.1626 18.8895 16.1973 18.8264 16.232C18.7002 16.3014 18.574 16.3645 18.4446 16.4245C18.3311 16.4749 18.2175 16.5223 18.1008 16.5633C17.9746 16.6106 17.8452 16.6516 17.7159 16.6863C17.5234 16.7399 17.3247 16.7809 17.1259 16.8125C16.9808 16.8346 16.8357 16.8504 16.6874 16.863C16.5328 16.8724 16.3751 16.8787 16.2173 16.8756C16.0438 16.8724 15.8703 16.863 15.6936 16.844C15.5643 16.8314 15.435 16.8125 15.3056 16.7873C15.192 16.7683 15.0785 16.7431 14.9649 16.7178C14.9049 16.7021 14.845 16.6895 14.7851 16.6737C14.6179 16.6295 14.4538 16.5822 14.2898 16.5349C14.2077 16.5096 14.1257 16.4875 14.0437 16.4623C13.9206 16.4245 13.7976 16.3897 13.6777 16.3519C13.5768 16.3203 13.479 16.2888 13.378 16.2572C13.2834 16.2257 13.1887 16.1942 13.0941 16.1626C13.031 16.1405 12.9647 16.1184 12.9016 16.0964C12.8228 16.0711 12.7471 16.0427 12.6682 16.0143C12.6114 15.9954 12.5578 15.9765 12.501 15.9544C12.3906 15.9134 12.2802 15.8755 12.1729 15.8345C12.1098 15.8093 12.0467 15.7872 11.9836 15.7619C11.8984 15.7304 11.8132 15.6957 11.7312 15.6641C11.6429 15.6294 11.5514 15.5947 11.4631 15.5569C11.4063 15.5348 11.3463 15.5096 11.2895 15.4875C11.217 15.4591 11.1476 15.4275 11.075 15.3991C11.0214 15.3771 10.9646 15.3518 10.911 15.3297C10.8542 15.3045 10.7974 15.2793 10.7406 15.254C10.6901 15.2319 10.6428 15.2099 10.5923 15.1878C10.5482 15.1688 10.5008 15.1468 10.4567 15.1278C10.4094 15.1057 10.3652 15.0868 10.3179 15.0647C10.2705 15.0427 10.2232 15.0206 10.1759 14.9985C10.116 14.9701 10.056 14.9417 9.99608 14.9165C9.93299 14.8881 9.87304 14.8565 9.80995 14.8281C9.7437 14.7966 9.67745 14.765 9.6112 14.7303C9.55441 14.7019 9.49762 14.6735 9.44084 14.6483C6.45324 13.1592 3.80321 11.1717 1.54438 8.76145C1.43081 8.64157 1.23206 8.72044 1.23206 8.88449L1.23836 18.0933C1.23836 18.494 1.43712 18.8726 1.77153 19.0934C3.86631 20.4878 6.38699 21.2986 9.09696 21.2986Z\"\n        fill=\"#3370FF\" />\n  <path d=\"M23.7322 9.29488C22.7226 8.79642 21.5838 8.5188 20.3818 8.5188C19.6688 8.5188 18.9747 8.6166 18.3217 8.80273C18.246 8.82481 18.1703 8.8469 18.0977 8.86898C18.0441 8.88476 17.9905 8.90368 17.94 8.91946C17.8359 8.95416 17.7318 8.99202 17.6276 9.03303C17.4447 9.10559 17.2617 9.18446 17.085 9.26964C16.8957 9.36113 16.7128 9.45893 16.5329 9.56619C16.35 9.67345 16.1701 9.79018 15.9998 9.91322C15.8767 10.0016 15.7569 10.093 15.637 10.1877C15.5076 10.2918 15.3846 10.3991 15.2616 10.5095C15.1953 10.5694 15.1322 10.6325 15.066 10.6925L14.7315 11.0206L13.3939 12.3424L13.1636 12.5696L13.0879 12.6453C13.05 12.6831 13.0122 12.7178 12.9775 12.7557C12.9586 12.7746 12.9396 12.7904 12.9207 12.8093C12.8923 12.8377 12.8639 12.863 12.8355 12.8882C12.804 12.9166 12.7724 12.9481 12.7409 12.9765C11.9143 13.7368 10.9931 14.3899 9.99304 14.923C10.053 14.9514 10.1129 14.9798 10.1729 15.0051C10.2202 15.0271 10.2675 15.0492 10.3148 15.0713C10.359 15.0934 10.4063 15.1123 10.4536 15.1344C10.4978 15.1533 10.5451 15.1754 10.5893 15.1943C10.6398 15.2164 10.6871 15.2385 10.7376 15.2606C10.7944 15.2858 10.8511 15.3111 10.9079 15.3363C10.9616 15.3584 11.0184 15.3836 11.072 15.4057C11.1445 15.4373 11.2139 15.4657 11.2865 15.4941C11.3433 15.5193 11.4032 15.5414 11.46 15.5635C11.5484 15.5982 11.6367 15.636 11.7282 15.6707C11.8134 15.7023 11.8954 15.737 11.9806 15.7685C12.0437 15.7938 12.1068 15.8158 12.1699 15.8411C12.2803 15.8821 12.3875 15.9231 12.498 15.961C12.5547 15.9799 12.6084 16.002 12.6652 16.0209C12.744 16.0493 12.8197 16.0745 12.8986 16.1029C12.9617 16.125 13.028 16.1471 13.0911 16.1692C13.1857 16.2007 13.2803 16.2323 13.375 16.2638C13.4728 16.2954 13.5737 16.3269 13.6747 16.3585C13.7977 16.3963 13.9176 16.4342 14.0406 16.4689C14.1227 16.4941 14.2047 16.5162 14.2867 16.5414C14.4508 16.5888 14.618 16.6361 14.782 16.6803C14.842 16.696 14.9019 16.7118 14.9618 16.7244C15.0754 16.7528 15.189 16.7749 15.3026 16.7938C15.4319 16.8159 15.5613 16.8348 15.6906 16.8506C15.8673 16.8695 16.0408 16.8822 16.2143 16.8822C16.372 16.8853 16.5298 16.879 16.6844 16.8695C16.8326 16.8601 16.9778 16.8412 17.1229 16.8191C17.3248 16.7875 17.5204 16.7465 17.7128 16.6929C17.8422 16.6582 17.9715 16.6172 18.0977 16.5698C18.2144 16.5257 18.328 16.4815 18.4416 16.4279C18.5709 16.3679 18.7003 16.3048 18.8233 16.2354C18.8833 16.2007 18.9464 16.166 19.0063 16.1282C19.0631 16.0935 19.1199 16.0556 19.1767 16.0178C19.265 15.9578 19.3533 15.8947 19.4385 15.8316C19.5111 15.7748 19.5836 15.718 19.653 15.6581C19.7792 15.5508 19.8991 15.4341 20.0158 15.3142C20.0726 15.2543 20.1294 15.1943 20.183 15.1313C20.2524 15.0524 20.3187 14.9704 20.3849 14.8852C20.4354 14.8189 20.4859 14.7495 20.5364 14.6801C20.672 14.4845 20.7982 14.2763 20.9118 14.0586L21.0411 13.7999L22.2084 11.4748L22.2053 11.4812C22.5807 10.6578 23.1012 9.91953 23.7322 9.29488Z\"\n        fill=\"#133C9A\" />\n</svg>",
  "notifier-email": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"2\" y=\"3\" width=\"20\" height=\"18\" rx=\"4\" fill=\"#F5F5F5\"/><path d=\"M5 7a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7Z\" fill=\"#fff\" stroke=\"#6B7280\" stroke-width=\"1.5\"/><path d=\"m5 7 7 5 7-5\" fill=\"none\" stroke=\"#6B7280\" stroke-width=\"1.5\" stroke-linecap=\"round\"/></svg>",
  "notifier-datadog": "<svg fill=\"#632CA6\" role=\"img\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><title>Datadog</title><path d=\"M19.57 17.04l-1.997-1.316-1.665 2.782-1.937-.567-1.706 2.604.087.82 9.274-1.71-.538-5.794zm-8.649-2.498l1.488-.204c.241.108.409.15.697.223.45.117.97.23 1.741-.16.18-.088.553-.43.704-.625l6.096-1.106.622 7.527-10.444 1.882zm11.325-2.712l-.602.115L20.488 0 .789 2.285l2.427 19.693 2.306-.334c-.184-.263-.471-.581-.96-.989-.68-.564-.44-1.522-.039-2.127.53-1.022 3.26-2.322 3.106-3.956-.056-.594-.15-1.368-.702-1.898-.02.22.017.432.017.432s-.227-.289-.34-.683c-.112-.15-.2-.199-.319-.4-.085.233-.073.503-.073.503s-.186-.437-.216-.807c-.11.166-.137.48-.137.48s-.241-.69-.186-1.062c-.11-.323-.436-.965-.343-2.424.6.421 1.924.321 2.44-.439.171-.251.288-.939-.086-2.293-.24-.868-.835-2.16-1.066-2.651l-.028.02c.122.395.374 1.223.47 1.625.293 1.218.372 1.642.234 2.204-.116.488-.397.808-1.107 1.165-.71.358-1.653-.514-1.713-.562-.69-.55-1.224-1.447-1.284-1.883-.062-.477.275-.763.445-1.153-.243.07-.514.192-.514.192s.323-.334.722-.624c.165-.109.262-.178.436-.323a9.762 9.762 0 0 0-.456.003s.42-.227.855-.392c-.318-.014-.623-.003-.623-.003s.937-.419 1.678-.727c.509-.208 1.006-.147 1.286.257.367.53.752.817 1.569.996.501-.223.653-.337 1.284-.509.554-.61.99-.688.99-.688s-.216.198-.274.51c.314-.249.66-.455.66-.455s-.134.164-.259.426l.03.043c.366-.22.797-.394.797-.394s-.123.156-.268.358c.277-.002.838.012 1.056.037 1.285.028 1.552-1.374 2.045-1.55.618-.22.894-.353 1.947.68.903.888 1.609 2.477 1.259 2.833-.294.295-.874-.115-1.516-.916a3.466 3.466 0 0 1-.716-1.562 1.533 1.533 0 0 0-.497-.85s.23.51.23.96c0 .246.03 1.165.424 1.68-.039.076-.057.374-.1.43-.458-.554-1.443-.95-1.604-1.067.544.445 1.793 1.468 2.273 2.449.453.927.186 1.777.416 1.997.065.063.976 1.197 1.15 1.767.306.994.019 2.038-.381 2.685l-1.117.174c-.163-.045-.273-.068-.42-.153.08-.143.241-.5.243-.572l-.063-.111c-.348.492-.93.97-1.414 1.245-.633.359-1.363.304-1.838.156-1.348-.415-2.623-1.327-2.93-1.566 0 0-.01.191.048.234.34.383 1.119 1.077 1.872 1.56l-1.605.177.759 5.908c-.337.048-.39.071-.757.124-.325-1.147-.946-1.895-1.624-2.332-.599-.384-1.424-.47-2.214-.314l-.05.059a2.851 2.851 0 0 1 1.863.444c.654.413 1.181 1.481 1.375 2.124.248.822.42 1.7-.248 2.632-.476.662-1.864 1.028-2.986.237.3.481.705.876 1.25.95.809.11 1.577-.03 2.106-.574.452-.464.69-1.434.628-2.456l.714-.104.258 1.834 11.827-1.424zM15.05 6.848c-.034.075-.085.125-.007.37l.004.014.013.032.032.073c.14.287.295.558.552.696.067-.011.136-.019.207-.023.242-.01.395.028.492.08.009-.048.01-.119.005-.222-.018-.364.072-.982-.626-1.308-.264-.122-.634-.084-.757.068a.302.302 0 0 1 .058.013c.186.066.06.13.027.207m1.958 3.392c-.092-.05-.52-.03-.821.005-.574.068-1.193.267-1.328.372-.247.191-.135.523.047.66.511.382.96.638 1.432.575.29-.038.546-.497.728-.914.124-.288.124-.598-.058-.698m-5.077-2.942c.162-.154-.805-.355-1.556.156-.554.378-.571 1.187-.041 1.646.053.046.096.078.137.104a4.77 4.77 0 0 1 1.396-.412c.113-.125.243-.345.21-.745-.044-.542-.455-.456-.146-.749\"/></svg>",
  "notifier-grafana": "<svg fill=\"#F46800\" role=\"img\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><title>Grafana</title><path d=\"M23.02 10.59a8.578 8.578 0 0 0-.862-3.034 8.911 8.911 0 0 0-1.789-2.445c.337-1.342-.413-2.505-.413-2.505-1.292-.08-2.113.4-2.416.62-.052-.02-.102-.044-.154-.064-.22-.089-.446-.172-.677-.247-.231-.073-.47-.14-.711-.197a9.867 9.867 0 0 0-.875-.161C14.557.753 12.94 0 12.94 0c-1.804 1.145-2.147 2.744-2.147 2.744l-.018.093c-.098.029-.2.057-.298.088-.138.042-.275.094-.413.143-.138.055-.275.107-.41.166a8.869 8.869 0 0 0-1.557.87l-.063-.029c-2.497-.955-4.716.195-4.716.195-.203 2.658.996 4.33 1.235 4.636a11.608 11.608 0 0 0-.607 2.635C1.636 12.677.953 15.014.953 15.014c1.926 2.214 4.171 2.351 4.171 2.351.003-.002.006-.002.006-.005.285.509.615.994.986 1.446.156.19.32.371.488.548-.704 2.009.099 3.68.099 3.68 2.144.08 3.553-.937 3.849-1.173a9.784 9.784 0 0 0 3.164.501h.08l.055-.003.107-.002.103-.005.003.002c1.01 1.44 2.788 1.646 2.788 1.646 1.264-1.332 1.337-2.653 1.337-2.94v-.058c0-.02-.003-.039-.003-.06.265-.187.52-.387.758-.6a7.875 7.875 0 0 0 1.415-1.7c1.43.083 2.437-.885 2.437-.885-.236-1.49-1.085-2.216-1.264-2.354l-.018-.013-.016-.013a.217.217 0 0 1-.031-.02c.008-.092.016-.18.02-.27.011-.162.016-.323.016-.48v-.253l-.005-.098-.008-.135a1.891 1.891 0 0 0-.01-.13c-.003-.042-.008-.083-.013-.125l-.016-.124-.018-.122a6.215 6.215 0 0 0-2.032-3.73 6.015 6.015 0 0 0-3.222-1.46 6.292 6.292 0 0 0-.85-.048l-.107.002h-.063l-.044.003-.104.008a4.777 4.777 0 0 0-3.335 1.695c-.332.4-.592.84-.768 1.297a4.594 4.594 0 0 0-.312 1.817l.003.091c.005.055.007.11.013.164a3.615 3.615 0 0 0 .698 1.82 3.53 3.53 0 0 0 1.827 1.282c.33.098.66.14.971.137.039 0 .078 0 .114-.002l.063-.003c.02 0 .041-.003.062-.003.034-.002.065-.007.099-.01.007 0 .018-.003.028-.003l.031-.005.06-.008a1.18 1.18 0 0 0 .112-.02c.036-.008.072-.013.109-.024a2.634 2.634 0 0 0 .914-.415c.028-.02.056-.041.085-.065a.248.248 0 0 0 .039-.35.244.244 0 0 0-.309-.06l-.078.042c-.09.044-.184.083-.283.116a2.476 2.476 0 0 1-.475.096c-.028.003-.054.006-.083.006l-.083.002c-.026 0-.054 0-.08-.002l-.102-.006h-.012l-.024.006c-.016-.003-.031-.003-.044-.006-.031-.002-.06-.007-.091-.01a2.59 2.59 0 0 1-.724-.213 2.557 2.557 0 0 1-.667-.438 2.52 2.52 0 0 1-.805-1.475 2.306 2.306 0 0 1-.029-.444l.006-.122v-.023l.002-.031c.003-.021.003-.04.005-.06a3.163 3.163 0 0 1 1.352-2.29 3.12 3.12 0 0 1 .937-.43 2.946 2.946 0 0 1 .776-.101h.06l.07.002.045.003h.026l.07.005a4.041 4.041 0 0 1 1.635.49 3.94 3.94 0 0 1 1.602 1.662 3.77 3.77 0 0 1 .397 1.414l.005.076.003.075c.002.026.002.05.002.075 0 .024.003.052 0 .07v.065l-.002.073-.008.174a6.195 6.195 0 0 1-.08.639 5.1 5.1 0 0 1-.267.927 5.31 5.31 0 0 1-.624 1.13 5.052 5.052 0 0 1-3.237 2.014 4.82 4.82 0 0 1-.649.066l-.039.003h-.287a6.607 6.607 0 0 1-1.716-.265 6.776 6.776 0 0 1-3.4-2.274 6.75 6.75 0 0 1-.746-1.15 6.616 6.616 0 0 1-.714-2.596l-.005-.083-.002-.02v-.056l-.003-.073v-.096l-.003-.104v-.07l.003-.163c.008-.22.026-.45.054-.678a8.707 8.707 0 0 1 .28-1.355c.128-.444.286-.872.473-1.277a7.04 7.04 0 0 1 1.456-2.1 5.925 5.925 0 0 1 .953-.763c.169-.111.343-.213.524-.306.089-.05.182-.091.273-.135.047-.02.093-.042.138-.062a7.177 7.177 0 0 1 .714-.267l.145-.045c.049-.015.098-.026.148-.041.098-.029.197-.052.296-.076.049-.013.1-.02.15-.033l.15-.032.151-.028.076-.013.075-.01.153-.024c.057-.01.114-.013.171-.023l.169-.021c.036-.003.073-.008.106-.01l.073-.008.036-.003.042-.002c.057-.003.114-.008.171-.01l.086-.006h.023l.037-.003.145-.007a7.999 7.999 0 0 1 1.708.125 7.917 7.917 0 0 1 2.048.68 8.253 8.253 0 0 1 1.672 1.09l.09.077.089.078c.06.052.114.107.171.159.057.052.112.106.166.16.052.055.107.107.159.164a8.671 8.671 0 0 1 1.41 1.978c.012.026.028.052.04.078l.04.078.075.156c.023.051.05.1.07.153l.065.15a8.848 8.848 0 0 1 .45 1.34.19.19 0 0 0 .201.142.186.186 0 0 0 .172-.184c.01-.246.002-.532-.024-.856z\"/></svg>",
  "notifier-flashcat": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"24\" height=\"24\" rx=\"7\" fill=\"#FF6B00\"/><path d=\"M5.5 9.2 8.8 5l2.4 4.1L14 5l3.5 4.2-1.7 9.3H7.2L5.5 9.2Z\" fill=\"#fff\"/><circle cx=\"9.5\" cy=\"12.2\" r=\"0.9\" fill=\"#FF6B00\"/><circle cx=\"14.5\" cy=\"12.2\" r=\"0.9\" fill=\"#FF6B00\"/><path d=\"M9.8 15.2c1.4.9 2.9.9 4.4 0\" stroke=\"#FF6B00\" stroke-width=\"1.1\" fill=\"none\" stroke-linecap=\"round\"/></svg>",
  "notifier-nightingale": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"24\" height=\"24\" rx=\"7\" fill=\"#1F3A5F\"/><path d=\"M6 15.8c2.8 1.5 5.5 1.5 8.3 0l-1-4.6 3.2 1.6-1.7-4.6-3.4 2.2-2.7-2.5-1.1 3.3L4.5 13l1.5 2.8Z\" fill=\"#fff\"/><circle cx=\"15.7\" cy=\"7.1\" r=\"0.8\" fill=\"#F6C343\"/></svg>",
  "clickhouse-log-sink": "<svg fill=\"#FFCC01\" role=\"img\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><title>ClickHouse</title><path d=\"M21.333 10H24v4h-2.667ZM16 1.335h2.667v21.33H16Zm-5.333 0h2.666v21.33h-2.666ZM0 22.665V1.335h2.667v21.33zm5.333-21.33H8v21.33H5.333Z\"/></svg>",
  "loki-log-sink": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"24\" height=\"24\" rx=\"7\" fill=\"#F46800\"/><path d=\"M7 6v12M10.5 6v12M14 6v12M17.5 6v7\" stroke=\"#fff\" stroke-width=\"2.2\" stroke-linecap=\"round\"/></svg>",
  "aliyun-connector": "<svg fill=\"#FF6A00\" role=\"img\" viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><title>Alibaba Cloud</title><path d=\"M3.996 4.517h5.291L8.01 6.324 4.153 7.506a1.668 1.668 0 0 0-1.165 1.601v5.786a1.668 1.668 0 0 0 1.165 1.6l3.857 1.183 1.277 1.807H3.996A3.996 3.996 0 0 1 0 15.487V8.513a3.996 3.996 0 0 1 3.996-3.996m16.008 0h-5.291l1.277 1.807 3.857 1.182c.715.227 1.17.889 1.165 1.601v5.786a1.668 1.668 0 0 1-1.165 1.6l-3.857 1.183-1.277 1.807h5.291A3.996 3.996 0 0 0 24 15.487V8.513a3.996 3.996 0 0 0-3.996-3.996m-4.007 8.345H8.002v-1.804h7.995Z\"/></svg>",
  "tencent-connector": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"24\" height=\"24\" rx=\"7\" fill=\"#0052D9\"/><path d=\"M6 15.5c2.2 1.8 4.5 2.6 6.9 2.4 3-.2 5.1-1.8 5.1-3.9 0-2-1.9-3.2-4.6-3.2-1.2 0-2.3.2-3.2.7.5-1.5 2-2.6 4.1-2.6 1 0 1.9.2 2.7.5-1-2-3-3.1-5.4-3.1C8.2 6.3 5.8 8.8 5.8 12c0 1.3.1 2.4 0 3.5Z\" fill=\"#fff\"/></svg>",
  "dogecloud-connector": "<svg viewBox=\"0 0 24 24\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"24\" height=\"24\" rx=\"7\" fill=\"#6C5CE7\"/><path d=\"M7 8.5c2.2-1.2 4.5-1.2 6.8 0 2.1 1.1 3.2 2.8 3.2 4.9 0 2.2-1.1 3.9-3.2 5-2.3 1.2-4.6 1.2-6.8 0V8.5Z\" fill=\"#fff\"/><path d=\"M9.7 11.3h2.1c1 0 1.7.7 1.7 1.7s-.7 1.7-1.7 1.7H9.7v-3.4Z\" fill=\"#6C5CE7\"/></svg>",
  "aws-s3-connector": "<svg viewBox=\"0 0 256 153\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" preserveAspectRatio=\"xMidYMid\"><g><path d=\"M72.392053,55.4384106 C72.392053,58.5748344 72.7311258,61.1178808 73.3245033,62.9827815 C74.002649,64.8476821 74.8503311,66.8821192 76.0370861,69.0860927 C76.4609272,69.7642384 76.6304636,70.4423841 76.6304636,71.0357616 C76.6304636,71.8834437 76.1218543,72.7311258 75.0198675,73.5788079 L69.6794702,77.1390728 C68.9165563,77.6476821 68.1536424,77.9019868 67.4754967,77.9019868 C66.6278146,77.9019868 65.7801325,77.4781457 64.9324503,76.7152318 C63.7456954,75.4437086 62.7284768,74.0874172 61.8807947,72.7311258 C61.0331126,71.2900662 60.1854305,69.6794702 59.2529801,67.7298013 C52.6410596,75.5284768 44.3337748,79.4278146 34.3311258,79.4278146 C27.210596,79.4278146 21.5311258,77.3933775 17.3774834,73.3245033 C13.2238411,69.2556291 11.1046358,63.8304636 11.1046358,57.0490066 C11.1046358,49.8437086 13.6476821,43.994702 18.818543,39.586755 C23.989404,35.1788079 30.8556291,32.9748344 39.586755,32.9748344 C42.4688742,32.9748344 45.4357616,33.2291391 48.5721854,33.6529801 C51.7086093,34.0768212 54.9298013,34.7549669 58.3205298,35.5178808 L58.3205298,29.3298013 C58.3205298,22.8874172 56.9642384,18.394702 54.3364238,15.7668874 C51.6238411,13.1390728 47.0463576,11.8675497 40.5192053,11.8675497 C37.5523179,11.8675497 34.5006623,12.2066225 31.3642384,12.9695364 C28.2278146,13.7324503 25.1761589,14.6649007 22.2092715,15.8516556 C20.8529801,16.4450331 19.8357616,16.784106 19.2423841,16.9536424 C18.6490066,17.1231788 18.2251656,17.207947 17.8860927,17.207947 C16.6993377,17.207947 16.1059603,16.3602649 16.1059603,14.5801325 L16.1059603,10.4264901 C16.1059603,9.07019868 16.2754967,8.05298013 16.6993377,7.45960265 C17.1231788,6.86622517 17.8860927,6.27284768 19.0728477,5.6794702 C22.0397351,4.15364238 25.6,2.88211921 29.7536424,1.86490066 C33.9072848,0.762913907 38.3152318,0.254304636 42.9774834,0.254304636 C53.0649007,0.254304636 60.4397351,2.54304636 65.186755,7.1205298 C69.8490066,11.6980132 72.2225166,18.6490066 72.2225166,27.9735099 L72.2225166,55.4384106 L72.392053,55.4384106 Z M37.9761589,68.3231788 C40.7735099,68.3231788 43.6556291,67.8145695 46.7072848,66.797351 C49.7589404,65.7801325 52.4715232,63.9152318 54.7602649,61.3721854 C56.1165563,59.7615894 57.1337748,57.981457 57.6423841,55.9470199 C58.1509934,53.9125828 58.4900662,51.4543046 58.4900662,48.5721854 L58.4900662,45.0119205 C56.0317881,44.418543 53.4039735,43.9099338 50.6913907,43.5708609 C47.9788079,43.2317881 45.3509934,43.0622517 42.7231788,43.0622517 C37.0437086,43.0622517 32.8900662,44.1642384 30.0927152,46.4529801 C27.2953642,48.7417219 25.9390728,51.9629139 25.9390728,56.2013245 C25.9390728,60.1854305 26.9562914,63.1523179 29.0754967,65.186755 C31.1099338,67.3059603 34.0768212,68.3231788 37.9761589,68.3231788 Z M106.045033,77.4781457 C104.519205,77.4781457 103.501987,77.2238411 102.823841,76.6304636 C102.145695,76.1218543 101.552318,74.9350993 101.043709,73.3245033 L81.1231788,7.7986755 C80.6145695,6.10331126 80.3602649,5.0013245 80.3602649,4.40794702 C80.3602649,3.05165563 81.0384106,2.28874172 82.394702,2.28874172 L90.7019868,2.28874172 C92.3125828,2.28874172 93.4145695,2.54304636 94.007947,3.13642384 C94.6860927,3.64503311 95.194702,4.83178808 95.7033113,6.44238411 L109.944371,62.5589404 L123.168212,6.44238411 C123.592053,4.74701987 124.100662,3.64503311 124.778808,3.13642384 C125.456954,2.62781457 126.643709,2.28874172 128.169536,2.28874172 L134.950993,2.28874172 C136.561589,2.28874172 137.663576,2.54304636 138.341722,3.13642384 C139.019868,3.64503311 139.613245,4.83178808 139.952318,6.44238411 L153.345695,63.2370861 L168.010596,6.44238411 C168.519205,4.74701987 169.112583,3.64503311 169.70596,3.13642384 C170.384106,2.62781457 171.486093,2.28874172 173.011921,2.28874172 L180.895364,2.28874172 C182.251656,2.28874172 183.01457,2.96688742 183.01457,4.40794702 C183.01457,4.83178808 182.929801,5.25562914 182.845033,5.76423841 C182.760265,6.27284768 182.590728,6.95099338 182.251656,7.88344371 L161.822517,73.4092715 C161.313907,75.1046358 160.72053,76.2066225 160.042384,76.7152318 C159.364238,77.2238411 158.262252,77.5629139 156.821192,77.5629139 L149.531126,77.5629139 C147.92053,77.5629139 146.818543,77.3086093 146.140397,76.7152318 C145.462252,76.1218543 144.868874,75.0198675 144.529801,73.3245033 L131.390728,18.6490066 L118.336424,73.2397351 C117.912583,74.9350993 117.403974,76.0370861 116.725828,76.6304636 C116.047682,77.2238411 114.860927,77.4781457 113.335099,77.4781457 L106.045033,77.4781457 Z M214.972185,79.7668874 C210.564238,79.7668874 206.156291,79.2582781 201.917881,78.2410596 C197.67947,77.2238411 194.37351,76.1218543 192.169536,74.8503311 C190.813245,74.0874172 189.880795,73.2397351 189.541722,72.4768212 C189.202649,71.7139073 189.033113,70.8662252 189.033113,70.1033113 L189.033113,65.7801325 C189.033113,64 189.711258,63.1523179 190.982781,63.1523179 C191.491391,63.1523179 192,63.2370861 192.508609,63.4066225 C193.017219,63.5761589 193.780132,63.9152318 194.627815,64.2543046 C197.509934,65.5258278 200.646358,66.5430464 203.952318,67.2211921 C207.343046,67.8993377 210.649007,68.2384106 214.039735,68.2384106 C219.380132,68.2384106 223.533775,67.3059603 226.415894,65.4410596 C229.298013,63.5761589 230.823841,60.8635762 230.823841,57.3880795 C230.823841,55.0145695 230.060927,53.0649007 228.535099,51.4543046 C227.009272,49.8437086 224.127152,48.402649 219.97351,47.0463576 L207.682119,43.2317881 C201.49404,41.2821192 196.916556,38.4 194.119205,34.5854305 C191.321854,30.8556291 189.880795,26.7019868 189.880795,22.2940397 C189.880795,18.7337748 190.643709,15.597351 192.169536,12.8847682 C193.695364,10.1721854 195.729801,7.7986755 198.272848,5.93377483 C200.815894,3.98410596 203.698013,2.54304636 207.088742,1.52582781 C210.47947,0.508609272 214.039735,0.0847682119 217.769536,0.0847682119 C219.634437,0.0847682119 221.584106,0.169536424 223.449007,0.42384106 C225.398675,0.678145695 227.178808,1.01721854 228.95894,1.35629139 C230.654305,1.78013245 232.264901,2.20397351 233.790728,2.71258278 C235.316556,3.22119205 236.503311,3.72980132 237.350993,4.2384106 C238.537748,4.91655629 239.38543,5.59470199 239.89404,6.35761589 C240.402649,7.03576159 240.656954,7.96821192 240.656954,9.15496689 L240.656954,13.1390728 C240.656954,14.9192053 239.978808,15.8516556 238.707285,15.8516556 C238.029139,15.8516556 236.927152,15.5125828 235.486093,14.8344371 C230.654305,12.6304636 225.229139,11.5284768 219.210596,11.5284768 C214.378808,11.5284768 210.564238,12.2913907 207.936424,13.9019868 C205.308609,15.5125828 203.952318,17.9708609 203.952318,21.4463576 C203.952318,23.8198675 204.8,25.8543046 206.495364,27.4649007 C208.190728,29.0754967 211.327152,30.6860927 215.819868,32.1271523 L227.856954,35.9417219 C233.960265,37.8913907 238.368212,40.6039735 240.996026,44.0794702 C243.623841,47.5549669 244.895364,51.5390728 244.895364,55.9470199 C244.895364,59.592053 244.13245,62.8980132 242.691391,65.7801325 C241.165563,68.6622517 239.131126,71.205298 236.503311,73.2397351 C233.875497,75.3589404 230.739073,76.8847682 227.09404,77.986755 C223.27947,79.1735099 219.295364,79.7668874 214.972185,79.7668874 Z\" fill=\"#252F3E\" fill-rule=\"nonzero\"></path><path d=\"M230.993377,120.964238 C203.104636,141.562914 162.58543,152.498013 127.745695,152.498013 C78.9192053,152.498013 34.9245033,134.442384 1.69536424,104.434437 C-0.932450331,102.060927 1.4410596,98.8397351 4.57748344,100.704636 C40.5192053,121.557616 84.8529801,134.188079 130.712583,134.188079 C161.65298,134.188079 195.645033,127.745695 226.924503,114.521854 C231.586755,112.402649 235.570861,117.57351 230.993377,120.964238 Z M242.606623,107.740397 C239.046358,103.162914 219.04106,105.536424 209.970861,106.638411 C207.258278,106.977483 206.834437,104.603974 209.292715,102.823841 C225.229139,91.6344371 251.422517,94.8556291 254.474172,98.5854305 C257.525828,102.4 253.62649,128.593377 238.707285,141.139073 C236.418543,143.088742 234.21457,142.071523 235.231788,139.528477 C238.622517,131.136424 246.166887,112.233113 242.606623,107.740397 Z\" fill=\"#FF9900\"></path></g></svg>",

};
const pluginCopy = {
  zh: {
    "edr-waf-correlation": { name: "EDR 事件关联", summary: "关联 WAF、认证、挑战、限流与 Origin 事件，生成可审计的风险提示。仅异步观察，不读取主机进程、文件或原始请求。" },
    "duckdb-analysis": { name: "DuckDB 审计分析", summary: "在宿主提供的一次性沙箱中读取脱敏 Parquet 审计快照，执行固定分析模板，输出可追溯的 analysis-record。不执行任意 SQL。" },
    "notifier-dingtalk": { name: "钉钉通知", summary: "把 CheeseWAF 告警投递到钉钉群自定义机器人。支持加签与 @手机号；凭据由核心秘密存储管理，插件不直接出网。" },
    "notifier-feishu": { name: "飞书通知", summary: "把 CheeseWAF 告警投递到飞书群自定义机器人。支持文本与交互卡片、加签校验；凭据由核心秘密存储管理。" },
    "notifier-email": { name: "邮件通知", summary: "通过客户自有 SMTP 服务器发送告警邮件。支持 STARTTLS、隐式 TLS、UTF-8 主题与 Message-ID；不提供内置邮件中继。" },
    "notifier-datadog": { name: "Datadog 事件", summary: "把 CheeseWAF 告警写入 Datadog Events API，附带严重级别、规则标签与来源信息。API Key 由核心秘密存储管理，插件不直接出网。" },
    "notifier-grafana": { name: "Grafana 注解", summary: "把告警写入 Grafana 注解时间线，便于和指标、日志、仪表盘联动排查。使用 Bearer Token 访问 Grafana HTTP API。" },
    "notifier-flashcat": { name: "快猫星云告警", summary: "把 CheeseWAF 告警推送到快猫星云事件接口，统一进入告警聚合、分派与值班流程。目标地址和凭据由核心统一管理。" },
    "notifier-nightingale": { name: "夜莺监控告警", summary: "把 CheeseWAF 告警推送到夜莺监控事件接口，复用夜莺的告警规则、屏蔽、认领与通知链路。" },
    "clickhouse-log-sink": { name: "ClickHouse 日志存储", summary: "把 WAF 访问与攻击日志异步写入 ClickHouse，支持按站点、时间、类别和关键词查询，适合大流量日志分析与审计。" },
    "loki-log-sink": { name: "Loki 日志聚合", summary: "把 WAF 日志推送到 Grafana Loki，按站点与严重级别打标签，使用 LogQL 与 Grafana 仪表盘联动排查。" },
    "aliyun-connector": { name: "阿里云连接器", summary: "统一接入阿里云 DNS、数字证书管理与 OSS 对象存储；AK/SK 只保存在核心秘密存储，连接器不直接持有凭据。" },
    "tencent-connector": { name: "腾讯云连接器", summary: "统一接入腾讯云 DNSPod、SSL 证书与 COS 对象存储；支持按站点绑定域名、证书和存储桶。" },
    "dogecloud-connector": { name: "多吉云连接器", summary: "接入多吉云 CDN 与 S3 兼容存储桶，用于静态资源加速、日志归档和审计快照投递。" },
    "aws-s3-connector": { name: "AWS S3 连接器", summary: "通过 S3 协议连接 AWS S3、MinIO、Ceph 等兼容对象存储，支持自定义 endpoint、路径风格与最小权限上传。" },
  },
  en: {
    "edr-waf-correlation": { name: "EDR event correlation", summary: "Correlates WAF, authentication, challenge, rate-limit and origin events into auditable risk hints. Observe-only; never reads host processes, files or raw requests." },
    "duckdb-analysis": { name: "DuckDB audit analysis", summary: "Runs fixed analysis templates in a host-provided one-shot sandbox over redacted Parquet snapshots and emits traceable analysis records. Arbitrary SQL is never executed." },
    "notifier-dingtalk": { name: "DingTalk notifications", summary: "Delivers CheeseWAF alerts to a DingTalk group custom bot with optional signing and @mentions. Credentials stay in the core secret store; the pack has no network egress." },
    "notifier-feishu": { name: "Feishu notifications", summary: "Delivers CheeseWAF alerts to a Feishu group custom bot with text or interactive cards and optional signature verification. Credentials stay in the core secret store." },
    "notifier-email": { name: "Email notifications", summary: "Sends alert email through the customer's own SMTP server with STARTTLS, implicit TLS, UTF-8 subjects and Message-ID. No hosted relay is provided." },
    "notifier-datadog": { name: "Datadog events", summary: "Writes CheeseWAF alerts into the Datadog Events API with severity, rule tags and source metadata. The API key stays in the core secret store; the pack has no egress." },
    "notifier-grafana": { name: "Grafana annotations", summary: "Writes alerts into the Grafana annotation timeline for correlation with metrics, logs and dashboards. Uses a Bearer token against the Grafana HTTP API." },
    "notifier-flashcat": { name: "Flashcat alerts", summary: "Pushes CheeseWAF alerts into the Flashcat event endpoint for aggregation, routing and on-call workflows. Destination and credentials are core-owned." },
    "notifier-nightingale": { name: "Nightingale alerts", summary: "Pushes CheeseWAF alerts into the Nightingale event endpoint, reusing its alert rules, silences, claims and notification pipeline." },
    "clickhouse-log-sink": { name: "ClickHouse log sink", summary: "Writes WAF access and attack logs asynchronously to ClickHouse with site, time, category and keyword queries for high-volume analysis and audit." },
    "loki-log-sink": { name: "Loki log sink", summary: "Pushes WAF logs to Grafana Loki with site and severity labels, queryable through LogQL and Grafana dashboards." },
    "aliyun-connector": { name: "Alibaba Cloud connector", summary: "Connects Alibaba Cloud DNS, certificate management and OSS object storage. AK/SK stay in the core secret store, never in the connector." },
    "tencent-connector": { name: "Tencent Cloud connector", summary: "Connects Tencent Cloud DNSPod, SSL certificates and COS object storage, with per-site domain, certificate and bucket bindings." },
    "dogecloud-connector": { name: "DogeCloud connector", summary: "Connects DogeCloud CDN and S3-compatible buckets for static acceleration, log archive and audit snapshot delivery." },
    "aws-s3-connector": { name: "AWS S3 connector", summary: "Connects AWS S3, MinIO, Ceph and other S3-compatible object storage with custom endpoint, path-style and least-privilege upload." },
  },
};
function pluginView(plugin) {
  const localized = pluginCopy[state.language]?.[plugin.pluginId];
  return localized ? { ...plugin, ...localized } : plugin;
}
function brandIcon(plugin) {
  const value = BRAND_ICONS[plugin.pluginId];
  if (!value) return null;
  const wrapper = document.createElement("span");
  wrapper.className = "brand-icon";
  wrapper.innerHTML = value;
  return wrapper;
}

const categoryKeys = { all: "categoryAll", security: "categorySecurity", intelligence: "categoryIntelligence", notifications: "categoryNotifications", analysis: "categoryAnalysis", tools: "categoryTools" };
const categoryIcons = { security: "shield", intelligence: "radar", notifications: "bell", analysis: "chart", tools: "code" };
const extensionTypeKeys = { "notifier-provider": "extensionNotifier", "storage-provider": "extensionStorage", "extension-descriptor": "extensionDescriptor" };
function extensionTypeKey(plugin) {
  if (plugin.extensionType === "extension-descriptor" && /-connector$/.test(plugin.pluginId)) return "extensionCloud";
  if (plugin.extensionType === "extension-descriptor" && /(?:log-sink|observability)/.test(plugin.pluginId)) return "extensionObservability";
  return extensionTypeKeys[plugin.extensionType] || "extensionDescriptor";
}
const extensionIcons = { "notifier-provider": "bell", "storage-provider": "chart", "extension-descriptor": "puzzle" };
const trustKeys = { official: "trustOfficial", enterprise: "trustEnterprise", community: "trustCommunity", personal: "trustPersonal", test: "trustTest", development: "trustDevelopment" };
const byId = id => document.getElementById(id);
const readPreference = key => { try { return localStorage.getItem(key); } catch { return null; } };
const savePreference = (key, value) => { try { localStorage.setItem(key, value); } catch { /* Preferences are optional. */ } };
const preferredLanguage = readPreference("cheesesec-store-language");
const state = {
  language: preferredLanguage === "zh" || preferredLanguage === "en" ? preferredLanguage : navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en",
  theme: readPreference("cheesesec-store-theme") || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
  category: "all", query: "", sort: "newest", items: [], status: "loading", currentPlugin: null,
};
if (!["light", "dark"].includes(state.theme)) state.theme = "light";
const t = key => copy[state.language][key] || key;
const docsRoot = () => `https://docs.cheesesec.com/${state.language === "zh" ? "zh/" : ""}docs/plugins/`;

function textLines(element, value) {
  const lines = String(value).split("\n");
  element.replaceChildren();
  lines.forEach((line, index) => {
    if (index) element.append(document.createElement("br"));
    element.append(document.createTextNode(line));
  });
}

function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#icon-${name}`);
  svg.append(use);
  return svg;
}

function applyLanguage() {
  document.documentElement.lang = state.language === "zh" ? "zh-CN" : "en";
  document.title = state.language === "zh" ? "CheeseSec · 插件商店" : "CheeseSec · Plugin store";
  document.querySelectorAll("[data-i18n]").forEach(element => textLines(element, t(element.dataset.i18n)));
  document.querySelectorAll(".docs-link").forEach(link => { link.href = docsRoot(); });
  document.querySelectorAll(".developer-link").forEach(link => { link.href = docsRoot(); });
  byId("plugin-search").placeholder = t("searchPlaceholder");
  byId("plugin-search").setAttribute("aria-label", t("searchLabel"));
  byId("clear-search").setAttribute("aria-label", t("clearSearch"));
  byId("sort-select").setAttribute("aria-label", t("sortLabel"));
  byId("close-dialog").setAttribute("aria-label", t("closeDialog"));
  document.querySelector(".brand").setAttribute("aria-label", t("homeLabel"));
  document.querySelector(".top-nav").setAttribute("aria-label", t("navigation"));
  byId("categories").setAttribute("aria-label", t("categories"));
  document.querySelector(".catalog-sidebar").setAttribute("aria-label", t("categories"));
  byId("language-toggle").textContent = state.language === "zh" ? "EN" : "中文";
  byId("language-toggle").setAttribute("aria-label", state.language === "zh" ? "Switch to English" : "切换到简体中文");
  updateTheme();
  render();
  if (state.currentPlugin && byId("plugin-dialog").open) fillDetails(state.currentPlugin);
}

function updateTheme() {
  document.documentElement.dataset.theme = state.theme;
  byId("theme-toggle").setAttribute("aria-label", t(state.theme === "dark" ? "themeLight" : "themeDark"));
  document.querySelector('meta[name="theme-color"]').content = state.theme === "dark" ? "#1b1b16" : "#fdfaf2";
}

function makeElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function renderCard(plugin) {
  // Planned packs render as cards so the roadmap is visible, but they carry no
  // download affordance: the card only opens the read-only detail dialog.
  const view = pluginView(plugin);
  const planned = plugin.planned === true;
  const card = makeElement("button", planned ? "plugin-card planned-card" : "plugin-card");
  card.type = "button";
  card.setAttribute("aria-label", `${t("detailsLabel")}: ${view.name}${planned ? ` · ${t("planned")}` : ""}`);
  const top = makeElement("div", "plugin-card-top");
  const glyph = makeElement("span", planned ? "plugin-card-icon planned-icon" : "plugin-card-icon");
  const brand = brandIcon(plugin);
  if (brand) glyph.append(brand);
  else glyph.append(icon(planned
    ? extensionIcons[plugin.extensionType] || "puzzle"
    : plugin.lifecycleExample ? "puzzle" : categoryIcons[plugin.category] || "puzzle"));
  top.append(glyph, planned
    ? makeElement("span", "planned-chip", t("planned"))
    : makeElement("span", "trust-chip", t(trustKeys[plugin.trustLevel] || "trustCommunity")));
  const bottom = makeElement("div", "plugin-card-bottom");
  bottom.append(makeElement("span", "plugin-card-version", `v${plugin.version}`),
    planned ? makeElement("span", "planned-note", t("notInstallable")) : icon("arrow"));
  card.append(top, makeElement("h3", "", view.name));
  if (planned) {
    card.append(makeElement("span", "platform-chip", t(extensionTypeKey(plugin))));
    card.append(makeElement("p", "plugin-purpose", view.summary));
  } else if (plugin.lifecycleExample) {
    card.append(makeElement("span", "platform-chip", plugin.lifecycleExample.platformLabel));
    card.append(makeElement("p", "plugin-purpose", t("lifecycleDescription")));
  } else if (view.summary) {
    card.append(makeElement("p", "plugin-purpose", view.summary));
  } else card.append(makeElement("p", "", t(categoryKeys[plugin.category] || "categoryTools")));
  card.append(bottom);
  card.addEventListener("click", () => {
    state.currentPlugin = plugin;
    fillDetails(plugin);
    byId("plugin-dialog").showModal();
  });
  return card;
}

function setCatalogState(kind) {
  const section = byId("catalog-state");
  section.dataset.state = kind;
  section.hidden = kind === "results";
  const titleKeys = { loading: "loadingTitle", empty: "emptyTitle", noResults: "noResultsTitle", error: "errorTitle" };
  const descriptionKeys = { loading: "loadingDescription", empty: "emptyDescription", noResults: "noResultsDescription", error: "errorDescription" };
  if (kind !== "results") {
    byId("state-title").textContent = t(titleKeys[kind]);
    byId("state-description").textContent = t(descriptionKeys[kind]);
  }
  byId("state-icon").replaceChildren(icon(kind === "error" ? "error" : kind === "noResults" ? "search" : "puzzle").firstElementChild);
  byId("retry-button").hidden = kind !== "error";
  byId("state-docs").hidden = kind !== "empty";
  byId("reset-filters").hidden = kind !== "noResults";
}

function render() {
  const grid = byId("plugin-grid");
  const filtered = filterCatalog(state.items.map(pluginView), { query: state.query, category: state.category, sort: state.sort });
  byId("catalog-title").textContent = t(categoryKeys[state.category]);
  byId("result-count").textContent = state.status === "loading" ? "—" : String(filtered.length);
  byId("clear-search").hidden = state.query.length === 0;
  document.querySelectorAll("[data-category]").forEach(button => {
    const selected = button.dataset.category === state.category;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  grid.replaceChildren();
  byId("catalog").setAttribute("aria-busy", String(state.status === "loading"));
  if (state.status === "loading") { setCatalogState("loading"); return; }
  if (state.status === "error") { setCatalogState("error"); return; }
  if (state.items.length === 0) { setCatalogState("empty"); return; }
  if (filtered.length === 0) { setCatalogState("noResults"); return; }
  setCatalogState("results");
  filtered.forEach(plugin => grid.append(renderCard(plugin)));
}

function fillDetails(plugin) {
  const view = pluginView(plugin);
  const planned = plugin.planned === true;
  byId("detail-title").textContent = view.name;
  const detailSummary = byId("detail-summary");
  detailSummary.textContent = view.summary || "";
  detailSummary.hidden = !view.summary;
  const detailIcon = document.querySelector(".detail-icon");
  const brand = brandIcon(plugin);
  if (detailIcon) detailIcon.replaceChildren(brand || icon(planned ? extensionIcons[plugin.extensionType] || "puzzle" : categoryIcons[plugin.category] || "puzzle"));
  byId("detail-namespace").textContent = plugin.namespace;
  byId("detail-trust").textContent = planned
    ? `${t("planned")} · ${t(trustKeys[plugin.trustLevel] || "trustCommunity")}`
    : t(trustKeys[plugin.trustLevel] || "trustCommunity");
  const fields = planned
    ? [["extensionType", t(extensionTypeKey(plugin))], ["version", plugin.version], ["planStatus", t("planned")], ["descriptorDigest", plugin.descriptorSha256], ["descriptorReference", plugin.descriptorUrl]]
    : [["version", plugin.version], ["publisher", plugin.source], ["packageSize", formatSize(plugin.size)], ["releaseSequence", String(plugin.releaseSequence)], ["digest", plugin.sha256]];
  if (!planned && plugin.lifecycleExample) fields.unshift(["compatibility", plugin.lifecycleExample.platformLabel]);
  const metadata = byId("detail-metadata");
  metadata.replaceChildren();
  fields.forEach(([label, value]) => { metadata.append(makeElement("dt", "", t(label)), makeElement("dd", "", value)); });
  const lifecycle = byId("detail-lifecycle");
  lifecycle.classList.toggle("detail-planned", planned);
  lifecycle.hidden = !planned && !plugin.lifecycleExample;
  lifecycle.replaceChildren();
  if (planned) {
    lifecycle.append(makeElement("strong", "", t("planned")), makeElement("p", "", t("plannedNote")));
  } else if (plugin.lifecycleExample) {
    lifecycle.append(makeElement("strong", "", t("lifecycleDescription")), makeElement("p", "", t("lifecycleDetails")), makeElement("p", "detail-platform", t(plugin.lifecycleExample.platform === "linux-amd64" ? "platformLinux" : "platformMac")));
  }
  // The install-oriented note only applies to published releases.
  const note = document.querySelector(".detail-note");
  if (note) note.hidden = planned;
  const download = byId("detail-download");
  if (planned) {
    // A planned pack has no archive, so the download control is removed rather
    // than left pointing at a descriptor or an empty href.
    download.hidden = true;
    download.removeAttribute("href");
    download.removeAttribute("download");
    download.setAttribute("aria-label", t("notInstallable"));
  } else {
    download.hidden = false;
    download.href = plugin.downloadUrl;
    download.setAttribute("download", plugin.downloadUrl.split("/").at(-1));
    download.setAttribute("aria-label", `${t("downloadPackage")}: ${view.name}${plugin.lifecycleExample ? ` · ${plugin.lifecycleExample.platformLabel}` : ""}`);
  }
}

function formatSize(value) {
  if (!Number.isFinite(value) || value < 0) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return new Intl.NumberFormat(state.language === "zh" ? "zh-CN" : "en", { maximumFractionDigits: index ? 1 : 0 }).format(value) + " " + units[index];
}

let requestVersion = 0;
async function loadCatalog() {
  const version = ++requestVersion;
  state.status = "loading";
  render();
  try {
    const response = await fetch("/v1/catalog/index.json", { credentials: "omit", redirect: "error", cache: "no-store", headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!response.ok || !response.headers.get("content-type")?.toLowerCase().includes("application/json")) throw new Error("catalog unavailable");
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > 1024 * 1024) throw new Error("catalog too large");
    // Published releases and planned packs share one display list; each item
    // keeps its own projection so planned entries never gain a download URL.
    const { plugins, extensions } = normalizeCatalog(JSON.parse(text));
    if (version !== requestVersion) return;
    state.items = [...plugins, ...extensions];
    state.status = "ready";
  } catch {
    if (version !== requestVersion) return;
    state.status = "error";
    state.items = [];
  }
  render();
}

byId("language-toggle").addEventListener("click", () => {
  state.language = state.language === "zh" ? "en" : "zh";
  savePreference("cheesesec-store-language", state.language);
  applyLanguage();
});
byId("theme-toggle").addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  savePreference("cheesesec-store-theme", state.theme);
  updateTheme();
});
byId("search-form").addEventListener("submit", event => { event.preventDefault(); state.query = byId("plugin-search").value.trim(); render(); });
byId("plugin-search").addEventListener("input", () => { state.query = byId("plugin-search").value.trim(); render(); });
byId("clear-search").addEventListener("click", () => { state.query = ""; byId("plugin-search").value = ""; render(); byId("plugin-search").focus(); });
byId("sort-select").addEventListener("change", event => { state.sort = event.target.value; render(); });
document.querySelectorAll("[data-category]").forEach(button => button.addEventListener("click", () => { state.category = button.dataset.category; render(); }));
byId("retry-button").addEventListener("click", loadCatalog);
byId("reset-filters").addEventListener("click", () => { state.query = ""; state.category = "all"; byId("plugin-search").value = ""; render(); byId("plugin-search").focus(); });
byId("close-dialog").addEventListener("click", () => byId("plugin-dialog").close());
byId("plugin-dialog").addEventListener("click", event => { if (event.target === byId("plugin-dialog")) { const bounds = event.target.getBoundingClientRect(); if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) event.target.close(); } });
byId("plugin-dialog").addEventListener("close", () => { state.currentPlugin = null; });
applyLanguage();
loadCatalog();
