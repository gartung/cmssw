#ifndef RecoAlgos_SingleElementCollectionSelector_h
#define RecoAlgos_SingleElementCollectionSelector_h
/** \class SingleElementCollectionSelector
 *
 * selects a subset of a collection based
 * on single element selection done via functor
 *
 * \author Luca Lista, INFN
 *
 * \version $Revision: 1.1 $
 *
 * $Id: SingleElementCollectionSelector.h,v 1.1 2009/03/03 13:07:28 llista Exp $
 *
 */
#include "FWCore/Framework/interface/ConsumesCollector.h"
#include "FWCore/ParameterSet/interface/ConfigurationDescriptions.h"
#include "CommonTools/UtilAlgos/interface/SelectionAdderTrait.h"
#include "CommonTools/UtilAlgos/interface/StoreContainerTrait.h"
#include "CommonTools/UtilAlgos/interface/ParameterAdapter.h"
#include "CommonTools/UtilAlgos/interface/SelectedOutputCollectionTrait.h"

namespace reco {
  namespace modules {
    template <typename S>
    struct SingleElementCollectionSelectorEventSetupInit;
  }
}  // namespace reco
namespace edm {
  class Event;
  class EventSetup;
}  // namespace edm

template <typename InputCollection,
          typename Selector,
          typename OutputCollection = typename ::helper::SelectedOutputCollectionTrait<InputCollection>::type,
          typename StoreContainer = typename ::helper::StoreContainerTrait<OutputCollection>::type,
          typename RefAdder = typename ::helper::SelectionAdderTrait<InputCollection, StoreContainer>::type>
struct SingleElementCollectionSelector {
  typedef InputCollection collection;
  typedef StoreContainer container;
  typedef Selector selector;
  typedef typename container::const_iterator const_iterator;
  SingleElementCollectionSelector(const edm::ParameterSet& cfg, edm::ConsumesCollector&& iC)
      : select_(reco::modules::make<Selector>(cfg, iC)) {}
  const_iterator begin() const { return selected_.begin(); }
  const_iterator end() const { return selected_.end(); }
  void select(const edm::Handle<InputCollection>& c, const edm::Event&, const edm::EventSetup&) {
    selected_.clear();
    for (size_t idx = 0; idx < c->size(); ++idx) {
      if (select_((*c)[idx]))
        addRef_(selected_, c, idx);
    }
  }

  static void fillPSetDescription(edm::ParameterSetDescription& desc) {
    reco::modules::ParameterAdapter<Selector>::fillPSetDescription(desc);
  };

private:
  container selected_;
  selector select_;
  RefAdder addRef_;
  friend struct reco::modules::SingleElementCollectionSelectorEventSetupInit<SingleElementCollectionSelector>;
};

#include "CommonTools/UtilAlgos/interface/EventSetupInitTrait.h"

namespace reco {
  namespace modules {
    template <typename S>
    struct SingleElementCollectionSelectorEventSetupInit {
      explicit SingleElementCollectionSelectorEventSetupInit(edm::ConsumesCollector iC) : esi_(iC) {}
      typedef typename EventSetupInit<typename S::selector>::type ESI;
      void init(S& s, const edm::Event& ev, const edm::EventSetup& es) { esi_.init(s.select_, ev, es); }
      ESI esi_;
    };

    template <typename I, typename S, typename O, typename C, typename R>
    struct EventSetupInit<SingleElementCollectionSelector<I, S, O, C, R> > {
      typedef SingleElementCollectionSelectorEventSetupInit<SingleElementCollectionSelector<I, S, O, C, R> > type;
    };
  }  // namespace modules
}  // namespace reco

#endif
