(function(){
  function TableTools(cfg){
    // cfg: { table, search, pager, pageSize, pageSizeSelect, filters:[{select, attr}] }
    this.table = document.querySelector(cfg.table);
    this.search = cfg.search ? document.querySelector(cfg.search) : null;
    this.pager = cfg.pager ? document.querySelector(cfg.pager) : null;
    this.pageSize = cfg.pageSize || 10;
    this.pageSizeSelect = cfg.pageSizeSelect ? document.querySelector(cfg.pageSizeSelect) : null;
    this.filters = (cfg.filters || []).map(function(f){
      return { el: document.querySelector(f.select), attr: f.attr };
    }).filter(function(f){ return !!f.el; });

    this.currentPage = 1;
    if(!this.table) return;

    this.tbody = this.table.tBodies[0];
    this.rows = Array.from(this.tbody.querySelectorAll("tr"));
    this.filtered = this.rows.slice();

    var self=this;

    function applyFilters(rows){
      var out = rows.slice();
      // attribute filters
      self.filters.forEach(function(f){
        var val = (f.el.value || "").trim();
        if(!val || val === "all") return;
        out = out.filter(function(r){
          var rv = (r.getAttribute("data-" + f.attr) || "").toString();
          return rv === val;
        });
      });
      return out;
    }

    function onChange(){
      var q = (self.search && self.search.value || "").toLowerCase().trim();
      var base = self.rows.slice();
      base = applyFilters(base);

      if(q){
        base = base.filter(function(r){
          return (r.innerText || "").toLowerCase().indexOf(q) !== -1;
        });
      }

      self.filtered = base;
      self.currentPage = 1;
      self.render();
    }

    if(this.search){
      this.search.addEventListener("input", onChange);
    }
    this.filters.forEach(function(f){
      f.el.addEventListener("change", onChange);
    });

    if(this.pageSizeSelect){
      this.pageSizeSelect.addEventListener("change", function(){
        var n = parseInt(self.pageSizeSelect.value || "10", 10);
        if(!isNaN(n) && n>0) self.pageSize = n;
        self.currentPage = 1;
        self.render();
      });
    }

    this.render = function(){
      var total = self.filtered.length;
      var pages = Math.max(1, Math.ceil(total / self.pageSize));
      if(self.currentPage > pages) self.currentPage = pages;

      var start = (self.currentPage-1)*self.pageSize;
      var end = start + self.pageSize;

      self.rows.forEach(function(r){ r.style.display="none"; });
      self.filtered.slice(start, end).forEach(function(r){ r.style.display=""; });

      if(self.pager){
        self.pager.innerHTML = "";
        var makeBtn = function(label, page, disabled, active){
          var b = document.createElement("button");
          b.type="button";
          b.className="btn btn-sm " + (active ? "btn-primary" : "btn-outline-secondary");
          b.disabled = !!disabled;
          b.textContent = label;
          b.addEventListener("click", function(){ self.currentPage = page; self.render(); });
          return b;
        };
        self.pager.appendChild(makeBtn("«", 1, self.currentPage===1));
        self.pager.appendChild(makeBtn("‹", Math.max(1,self.currentPage-1), self.currentPage===1));

        var windowSize = 5;
        var startP = Math.max(1, self.currentPage - Math.floor(windowSize/2));
        var endP = Math.min(pages, startP + windowSize - 1);
        startP = Math.max(1, endP - windowSize + 1);

        for(var p=startP; p<=endP; p++){
          self.pager.appendChild(makeBtn(String(p), p, false, p===self.currentPage));
        }

        self.pager.appendChild(makeBtn("›", Math.min(pages,self.currentPage+1), self.currentPage===pages));
        self.pager.appendChild(makeBtn("»", pages, self.currentPage===pages));
      }

      if(cfg.onRender){
        cfg.onRender({ total: total, pages: pages, page: self.currentPage, pageSize: self.pageSize });
      }
    };

    this.render();
  }

  window.TableTools = TableTools;
})();